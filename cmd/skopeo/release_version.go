package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/containers/skopeo/common/reqcli"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/spf13/cobra"
)


type Artifact struct {
	ID             uint       `json:"ID"`
	RepositoryName string    `json:"repository_name,omitempty"`
	Type           string    `json:"type"`
	MetaData       string    `json:"meta_data,omitempty"`
	Digest         string    `json:"digest,omitempty"`
	OriDigest      string    `json:"ori_digest"`
	NamespaceName string   `json:"namespace_name"`
	Tags          []string `json:"tags"`
	Name       		string `json:"name"`
	FilePath   	   string `json:"file_path"`
}

var pwd, _ = os.Getwd()

const (
	defaultContainerAuthConfigPath = "/run/user/%d/containers/auth.json"
	dockerImage = "DOCKER-IMAGE"
	dirType     = "dir"
)
type ReleaseVersion struct {
	Version   string      `json:"version"`
	Info  string      	  `json:"info"`
	CreatedAt time.Time   `json:"created_at"`
	Status    string      `json:"status"`
	Artifacts []*Artifact `json:"artifacts"`
}

type ReleaseVersionList  struct {
	Items   []*ReleaseVersion `json:"items"`
	Total   int               `json:"total"`
}

var dockerHomePath  = ".docker/config.json"

type dAuthConfig struct {
	Auth          string `json:"auth,omitempty"`
}

type dConfigFile struct {
	AuthConfigs map[string]dAuthConfig `json:"auths"`
}
func init() {
	os.Setenv("XDG_RUNTIME_DIR", fmt.Sprintf("/run/user/%d", os.Getuid()))
}

func readJSONFile(path string) (*dConfigFile, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &dConfigFile{}, nil
		}
		return nil, err
	}
	da := dConfigFile{}
	err = json.Unmarshal(data, &da)
	if err != nil {
		return nil, err
	}
	return &da, nil
}

type dockerAuthConfig struct {
	Auth          string `json:"auth,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
}

type dockerConfigFile struct {
	AuthConfigs map[string]dockerAuthConfig `json:"auths"`
	CredHelpers map[string]string           `json:"credHelpers,omitempty"`
}

func readDockerJSONFile(path string, legacyFormat bool) (*dockerConfigFile, error) {
	auths := &dockerConfigFile{}

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("path: %s is empty \n",  path)
			auths.AuthConfigs = map[string]dockerAuthConfig{}
			return auths, nil
		}
		return &dockerConfigFile{}, err
	}

	if legacyFormat {
		if err = json.Unmarshal(raw, &auths.AuthConfigs); err != nil {
			return &dockerConfigFile{}, errors.Wrapf(err, "error unmarshaling JSON at %q", path)
		}
		return auths, nil
	}

	if err = json.Unmarshal(raw, &auths); err != nil {
		return &dockerConfigFile{}, errors.Wrapf(err, "error unmarshaling JSON at %q", path)
	}

	if auths.AuthConfigs == nil {
		auths.AuthConfigs = map[string]dockerAuthConfig{}
	}
	if auths.CredHelpers == nil {
		auths.CredHelpers = make(map[string]string)
	}

	return auths, nil
}


type ReleaseVersionOptions struct {
	global            *globalOptions
	srcImage          *imageOptions
	destImage         *imageDestOptions
	retryOpts         *retry.RetryOptions
	version           string
	token             string
	src               string
	dest              string
	srcType           string
	destType          string
	destPath          string
	action            string
	removeSignatures  bool           // Do not copy signatures from the source image
	signByFingerprint string         // Sign the image using a GPG key with the specified fingerprint
	digestFile        string         // Write digest to this file
	format            optionalString // Force conversion of the image to a specified format
	quiet             bool           // Suppress output information when copying images
	all               bool           // Copy all of the images if the source is a list
	errors            []error
	lock              sync.Mutex
	bearerToken       *BearerToken
	httpSchema        string
	enableHttp        bool
}

func releaseVersionCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	srcFlags, srcOpts := imageFlags(global, sharedOpts, "src-", "screds")
	destFlags, destOpts := imageDestFlags(global, sharedOpts, "dest-", "dcreds")

	retryFlags, retryOpts := retryFlags()
	rvOpt := ReleaseVersionOptions{
		global: global,
		srcImage: srcOpts,
		destImage: destOpts,
		retryOpts: retryOpts,
		httpSchema: "https",
	}
	cmd := &cobra.Command{
		Use: "release-version [command options] SOURCE-VERSION DESTINATION-VERSION",
		Short:  "Download ReleaseVersion Artifacts",
		Long: "ReleaseVersion tool for hybrid cloud",
		RunE: commandAction(rvOpt.run),
	}

	adjustUsage(cmd)
	flags := cmd.Flags()

	flags.AddFlagSet(&retryFlags)
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&srcFlags)
	flags.AddFlagSet(&destFlags)

	flags.StringVar(&rvOpt.srcType, "src-type", "", "src-type: such as docker, dir, oci, default docker")
	flags.StringVar(&rvOpt.src, "src", "", "The release version src url")
	flags.StringVar(&rvOpt.dest, "dest", "", "The release version dest url")
	flags.StringVar(&rvOpt.destType, "dest-type", "", "dest-type: such as docker, dir, oci, default docker")

	flags.StringVar(&rvOpt.version, "version", "", "the release version")
	flags.StringVar(&rvOpt.token, "token", "", "oauth token")
	flags.StringVar(&rvOpt.action, "action", "", "cmd action")
	flags.BoolVar(&rvOpt.removeSignatures, "remove-signatures", false, "Do not copy signatures from SOURCE-IMAGE")
	flags.StringVar(&rvOpt.signByFingerprint, "sign-by", "", "Sign the image using a GPG key with the specified `FINGERPRINT`")
	flags.StringVar(&rvOpt.destPath, "dest-path", "", "The dest path to storage non docker image data")
	flags.BoolVar(&rvOpt.enableHttp, "http", false, "use http")
	if rvOpt.enableHttp {
		rvOpt.httpSchema = "http"
	}
	return cmd
}

type BearerToken struct {
	Token          string    `json:"token"`
	AccessToken    string    `json:"access_token"`
	ExpiresIn      int       `json:"expires_in"`
	IssuedAt       time.Time `json:"issued_at"`
	expirationTime time.Time
}

func (opts *ReleaseVersionOptions) getAuthToken() error {
	cli := reqcli.GetDefaultHttpClient()
	ud, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	da, err := readJSONFile(filepath.Join(ud, dockerHomePath))
	if err != nil {
		return err
	}
	authToken := ""
	for k, v := range da.AuthConfigs {
		if strings.Contains(opts.src, k) {
			authToken = v.Auth
			break
		}
	}
	if authToken == "" {
		dockerAuthConfig, err := readDockerJSONFile(fmt.Sprintf(defaultContainerAuthConfigPath, os.Getuid()), false)
		if err != nil {
			return err
		}
		for k, v := range dockerAuthConfig.AuthConfigs {
			if strings.Contains(opts.src, k) {
				authToken = v.Auth
				break
			}
		}
	}
	bt := BearerToken{}

	checkReq, err := http.NewRequestWithContext(context.TODO(),
		http.MethodGet,
		fmt.Sprintf("%s://%s/api/v1/check_alive", opts.httpSchema, opts.src), nil)
	if err != nil {
		return err
	}
	_, err = cli.Do(checkReq)
	if err != nil {
		opts.httpSchema = "http"
	}

	authReq, err := http.NewRequestWithContext(context.TODO(),
		http.MethodGet,
		fmt.Sprintf("%s://%s/api/v1/token", opts.httpSchema, opts.src), nil)
	if err != nil {
		return err
	}
	authReq.Header.Add("Authorization", fmt.Sprintf("Basic %s", authToken))
	authResp, err := cli.Do(authReq)
	if err != nil {
		return err
	}
	defer authResp.Body.Close()
	if err := json.NewDecoder(authResp.Body).Decode(&bt); err != nil {
		return err
	}
	opts.bearerToken = &bt
	return nil
}

func (opts *ReleaseVersionOptions) clearDestDir() {
	if opts.destType == dirType {
		pa := opts.getReleaseVersionPath(false)
		os.RemoveAll(pa)
	}
}

func (opts *ReleaseVersionOptions) getSrcReleaseVersion() (*ReleaseVersion, error) {
	data := []byte{}
	if opts.srcType == dirType {
		rPath := opts.getReleaseVersionPath(true)
		rConfPath := filepath.Join(rPath, fmt.Sprintf("%s.json", opts.version))
		var err error
		data, err = ioutil.ReadFile(rConfPath)
		if err != nil {
			return nil, err
		}
	} else {
		cli := reqcli.GetDefaultHttpClient()
		req, err := http.NewRequestWithContext(context.TODO(),
			http.MethodGet,
			fmt.Sprintf("%s://%s/api/v1/release-versions/%s", opts.httpSchema, opts.src, opts.version), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", opts.bearerToken.Token))
		resp, err := cli.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logrus.Errorf("get version %s resp status is: %d ", opts.version, resp.StatusCode)
			return nil, fmt.Errorf("get version %s resp status is: %d", opts.version, resp.StatusCode)
		}

		data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	}

	releaseVersion := ReleaseVersion{}
	if err := json.Unmarshal(data, &releaseVersion); err != nil {
		return nil, errors.Wrapf(err, "json decode release version")
	}
	return &releaseVersion, nil
}

func (opts *ReleaseVersionOptions) prepare() error {
	if opts.srcType != dirType {
		if opts.token != "" {
			opts.bearerToken = &BearerToken{
				Token: opts.token,
				AccessToken: opts.token,
			}
			return nil
		}
		err := opts.getAuthToken()
		if err != nil {
			return err
		}
	}
	opts.clearDestDir()
	return nil
}

func (opts *ReleaseVersionOptions) run(args []string, stdout io.Writer) error {
	if err := opts.prepare(); err != nil {
		return err
	}
	if opts.action == "list" {
		return opts.listReleaseVersion(args, stdout)
	}

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	releaseVersion, err := opts.getSrcReleaseVersion()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(len(releaseVersion.Artifacts))
	logrus.Info("begin to load artifacts")
	for _, arti := range releaseVersion.Artifacts {
		arti := arti
		go func(ctx context.Context, arti *Artifact, stdout io.Writer) {
			defer func() {
				wg.Done()
				if err := recover(); err != nil {
					opts.addError(fmt.Errorf("%v",err))
				}
			}()
			var err error
			if arti.Type != dockerImage {
				err = opts.copyBinaryArtifact(ctx, arti, stdout)
			} else {
				err = opts.copyDockerArtifact(ctx, arti, stdout)
			}
			if err != nil {
				opts.addError(err)
			}
		}(ctx, arti, stdout)
	}
	wg.Wait()
	for _, e := range opts.errors {
		if e != nil {
			stdout.Write([]byte(fmt.Sprintf("%+v", e)))
			err = errors.Wrapf(e, "%+v", err)
		}
	}
	if err != nil {
		return err
	}

	data, _ := json.Marshal(releaseVersion)
	ioutil.WriteFile(fmt.Sprintf("%s/%s.json", opts.getReleaseVersionPath(false), opts.version), data, 0644)
	printReleaseVersions([]*ReleaseVersion{releaseVersion})
	return  nil
}

func (opts *ReleaseVersionOptions) copyBinaryArtifact(ctx context.Context, artifact *Artifact, stdout io.Writer) error {
	dataPath := opts.getAndPrepareArtifactPath(artifact, false)
	cli := reqcli.GetDefaultHttpClient()
	req, err := http.NewRequestWithContext(context.TODO(),
		http.MethodGet,
		fmt.Sprintf("%s://%s/api/v1/artifactEncrypt/%d", opts.httpSchema, opts.src, artifact.ID), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", opts.bearerToken.Token))
	resp, _ := cli.Do(req)
	encryptKey := ""
	if resp != nil {
		encryptKey = resp.Header.Get("Blob-AESKey")
	}

	req, err = http.NewRequestWithContext(context.TODO(),
		http.MethodGet,
		fmt.Sprintf("%s://%s/api/v1/artifactDownload/%d", opts.httpSchema, opts.src, artifact.ID), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", opts.bearerToken.Token))
	resp, err = cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("download artifact %s resp status is: %d ", artifact.RepositoryName, resp.StatusCode)
		return fmt.Errorf("download artifact %s resp status is: %d ", artifact.RepositoryName, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if ba := strings.TrimSpace(resp.Header.Get("Blob-AESKey")); ba != "" {
		encryptKey = ba
	}
	if encryptKey == "" {
		fmt.Printf("artifact %s is not enrypt \n", artifact.RepositoryName)
		return ioutil.WriteFile(dataPath, body, 0777)
	}
	aesKey, nonce, err := parseBlobAesKey(encryptKey)
	if err != nil {
		return err
	}

	key, err := hex.DecodeString(aesKey)
	if err != nil {
		return fmt.Errorf("hex decode string encryKey: %s  err: %v", key, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes NewCipher err: %v", err)
	}
	stream := cipher.NewCTR(block, []byte(nonce))
	if err != nil {
		return fmt.Errorf("failed to New GCM, err: %v", err)
	}
	stream.XORKeyStream(body, body)
	fmt.Printf("artifact: %s storage path: %s \n", artifact.RepositoryName, dataPath)
	return ioutil.WriteFile(dataPath, body, 0777)
}

func parseBlobAesKey(aesKey string) (string, string, error) {
	buf, err := base64.StdEncoding.DecodeString(aesKey)
	if err != nil {
		return "", "", nil
	}
	strs := strings.Split(string(buf), ":")
	if len(strs) != 2 {
		return "", "", fmt.Errorf("invalid ase key: %s", string(buf))
	}
	return strs[0], strs[1], nil
}

func (opts *ReleaseVersionOptions) copyDockerArtifact(ctx context.Context, artifact *Artifact, stdout io.Writer) error {
	policyContext, err := opts.global.getPolicyContext()
	if err != nil {
		return fmt.Errorf("Error loading trust policy: %v", err)
	}
	defer policyContext.Destroy()

	tag := "latest"
	if len(artifact.Tags) > 0 {
		tag = artifact.Tags[0]
	}

	srcImage := fmt.Sprintf("docker://%s/%s:%s", opts.src, artifact.RepositoryName, tag)
	if opts.srcType == dirType {
		srcImage = fmt.Sprintf("dir:%s", opts.getArtifactPath(artifact, true))
	}
	srcRef, err := alltransports.ParseImageName(srcImage)
	if err != nil {
		return errors.Wrapf(err, "failed to parse image name: %s", srcImage)
	}
	destImage := fmt.Sprintf("docker://%s/%s:%s", opts.dest, artifact.RepositoryName, tag)
	if opts.destType == dirType {
		destImage = fmt.Sprintf("dir:%s", opts.getAndPrepareArtifactPath(artifact, false))
	}
	destRef, err := alltransports.ParseImageName(destImage)
	if err != nil {
		return errors.Wrapf(err, "failed to parse image name: %s", destImage)
	}
	sourceCtx, err := opts.srcImage.newSystemContext()
	if err != nil {
		return err
	}
	destinationCtx, err := opts.destImage.newSystemContext()
	if err != nil {
		return err
	}

	return retry.RetryIfNecessary(ctx, func() error {
		manifestBytes, err := copy.Image(ctx, policyContext, destRef, srcRef, &copy.Options{
			RemoveSignatures:      opts.removeSignatures,
			SignBy:                opts.signByFingerprint,
			ReportWriter:          stdout,
			SourceCtx:             sourceCtx,
			DestinationCtx:        destinationCtx,
			ImageListSelection:    copy.CopySystemImage,
		})
		if err != nil {
			return err
		}
		if opts.digestFile != "" {
			manifestDigest, err := manifest.Digest(manifestBytes)
			if err != nil {
				return err
			}
			if err = ioutil.WriteFile(opts.digestFile, []byte(manifestDigest.String()), 0644); err != nil {
				return fmt.Errorf("Failed to write digest to file %q: %v", opts.digestFile, err)
			}
		}
		return nil
	}, opts.retryOpts)
}

func (opts *ReleaseVersionOptions) listReleaseVersion(args []string, stdout io.Writer) error {
	list := ReleaseVersionList{Items: []*ReleaseVersion{}}
	if opts.srcType == dirType {
		rpath := opts.getReleaseVersionPath(true)
		parent := path.Dir(rpath)
		files, err := ioutil.ReadDir(parent)
		if err != nil {
			return err
		}
		for i := range files {
			if strings.Contains(files[i].Name(), opts.version) {
				jp := filepath.Join(parent, files[i].Name(), fmt.Sprintf("%s.json", files[i].Name()))
				_, err := os.Stat(jp)
				if err != nil {
					continue
				}
				rvData, err := ioutil.ReadFile(jp)
				if err != nil {
					return err
				}
				rv := ReleaseVersion{}
				if err := json.Unmarshal(rvData, &rv); err != nil {
					return err
				}
				list.Items = append(list.Items, &rv)
			}
		}
	} else {
		cli := reqcli.GetDefaultHttpClient()
		req, err := http.NewRequestWithContext(context.TODO(),
			http.MethodGet,
			fmt.Sprintf("%s://%s/api/v1/release-versions?search=%s", opts.httpSchema, opts.src, opts.version), nil)
		if err != nil {
			return err
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", opts.bearerToken.Token))
		resp, err := cli.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logrus.Errorf("list version %s resp status is: %d ", opts.version, resp.StatusCode)
			return fmt.Errorf("get version %s resp status is: %d", opts.version, resp.StatusCode)
		}

		if err = json.NewDecoder(resp.Body).Decode(&list); err != nil {
			return err
		}
	}

	printReleaseVersions(list.Items)
	return nil
}

func printReleaseVersions(rvs []*ReleaseVersion) {
	fmt.Printf("===================================== Release Version (%d): =======================================\n", len(rvs))
	for _, rv := range rvs {
		printReleaseVersion(rv)
	}
	fmt.Printf("===================================================================================================\n")
}

func printReleaseVersion(rv *ReleaseVersion) {
	fmt.Printf("Version:  %s \n", rv.Version)
	fmt.Printf("Status:   %s \n", rv.Status)
	fmt.Printf("Info: 	 %s \n", rv.Info)
	fmt.Printf("Artifacts: \n")
	for _, art := range rv.Artifacts {
		if art.Type == "DOCKER-IMAGE" {
			tag := ""
			for _, t := range art.Tags {
				if tag == "" {
					tag = t
				} else {
					tag = fmt.Sprintf("%s | %s", tag, t)
				}
			}
			fmt.Printf("    image: %s:%s \n", art.RepositoryName, tag)
			fmt.Printf("    digest: %s \n", art.Digest)
			fmt.Println()
		} else {
			fmt.Printf("    binary: %s \n", art.RepositoryName)
			fmt.Printf("    digest: %s \n", art.Digest)
			if art.OriDigest != "" {
				fmt.Printf("    ori digest: %s \n", art.OriDigest)
			}
			fmt.Println()
		}
	}
	fmt.Println()
}

func (opts *ReleaseVersionOptions) addError(err error) {
	if err == nil {
		return
	}
	opts.lock.Lock()
	if len(opts.errors) == 0 {
		opts.errors = []error{err}
	} else {
		opts.errors = append(opts.errors, err)
	}
	opts.lock.Unlock()
}

func (opts *ReleaseVersionOptions) getReleaseVersionPath(isSrc bool) string {
	if isSrc {
		return filepath.Join(opts.src, "release-version", opts.version)
	}
	if opts.destType == dirType {
		return filepath.Join(opts.dest, "release-version", opts.version)
	}
	rp := opts.destPath
	if rp == "" {
		rp = pwd
	}
	return filepath.Join(rp, "release-version", opts.version)
}

func (opts *ReleaseVersionOptions) getAndPrepareArtifactPath(artifact *Artifact, isSrc bool) string {
	p := opts.getArtifactPath(artifact, isSrc)
	os.RemoveAll(p)
	if artifact.Type == dockerImage {
		os.MkdirAll(p, 0777)
	} else {
		parentDir := path.Dir(p)
		os.MkdirAll(parentDir, 0777)
	}
	return p
}

func (opts *ReleaseVersionOptions) getArtifactPath(artifact *Artifact,isSrc bool) string {
	p := "images"
	if artifact.Type != dockerImage {
		p = "binary"
	}

	if isSrc {
		return filepath.Join(opts.src, "release-version", opts.version, p, opts.getArtifactName(artifact))
	}
	if opts.destType == dirType {
		return filepath.Join(opts.dest, "release-version", opts.version, p, opts.getArtifactName(artifact))
	}
	rp := opts.destPath
	if rp == "" {
		rp = pwd
	}
	return filepath.Join(rp, "release-version", opts.version, p, opts.getArtifactName(artifact))
}

func (opts *ReleaseVersionOptions) getArtifactName(arti *Artifact) string {
	if arti.Type != dockerImage {
		if arti.FilePath != "" {
			return arti.FilePath
		}
		if arti.Name != "" {
			return arti.Name
		}
		return arti.RepositoryName
	}

	tag := "latest"
	if len(arti.Tags) > 0 {
		tag = arti.Tags[0]
	}
	return fmt.Sprintf("%s:%s", arti.RepositoryName, tag)
}
