package dind

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/rancher/rke/docker"
	"github.com/rancher/rke/util"
	"github.com/sirupsen/logrus"
)

const (
	DINDImage           = "docker:24.0.9-dind"
	DINDContainerPrefix = "rke-dind"
	DINDPlane           = "dind"
	DINDNetwork         = "dind-network"
	DINDSubnet          = "172.18.0.0/16"
)

func StartUpDindContainer(ctx context.Context, dindAddress, dindNetwork, dindStorageDriver, dindDNS string) (string, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return "", err
	}
	// its recommended to use host's storage driver
	dockerInfo, err := cli.Info(ctx)
	if err != nil {
		return "", err
	}
	storageDriver := dindStorageDriver
	if len(storageDriver) == 0 {
		storageDriver = dockerInfo.Driver
	}

	// Get dind container name
	containerName := fmt.Sprintf("%s-%s", DINDContainerPrefix, dindAddress)
	_, err = cli.ContainerInspect(ctx, containerName)
	if err != nil {
		if !client.IsErrNotFound(err) {
			return "", err
		}
		if err := docker.UseLocalOrPull(ctx, cli, cli.DaemonHost(), DINDImage, DINDPlane, nil); err != nil {
			return "", err
		}
		binds := []string{
			fmt.Sprintf("/var/lib/kubelet-%s:/var/lib/kubelet:shared", containerName),
			"/etc/machine-id:/etc/machine-id:ro",
		}
		isLink, err := util.IsSymlink("/etc/resolv.conf")
		if err != nil {
			return "", err
		}
		if isLink {
			logrus.Infof("[%s] symlinked [/etc/resolv.conf] file detected. Using [%s] as DNS server.", DINDPlane, dindDNS)
		} else {
			binds = append(binds, "/etc/resolv.conf:/etc/resolv.conf")
		}
		imageCfg := &container.Config{
			Image: DINDImage,
			Entrypoint: []string{
				"sh",
				"-c",
				"mount --make-shared / && " +
					"mount --make-shared /sys && " +
					"mount --make-shared /var/lib/docker && " +
					"dockerd-entrypoint.sh --tls=false --storage-driver=" + storageDriver,
			},
			Hostname: dindAddress,
			Env:      []string{"DOCKER_TLS_CERTDIR="},
		}
		hostCfg := &container.HostConfig{
			Privileged: true,
			Binds:      binds,
			// this gets ignored if resolv.conf is bind mounted. So it's ok to have it anyway.
			DNS: []string{dindDNS},
			// Calico needs this
			Sysctls: map[string]string{
				"net.ipv4.conf.all.rp_filter": "1",
			},
		}
		resp, err := cli.ContainerCreate(ctx, imageCfg, hostCfg, nil, nil, containerName)
		if err != nil {
			return "", fmt.Errorf("Failed to create [%s] container on host [%s]: %v", containerName, cli.DaemonHost(), err)
		}

		if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
			return "", fmt.Errorf("Failed to start [%s] container on host [%s]: %v", containerName, cli.DaemonHost(), err)
		}
		logrus.Infof("[%s] Successfully started [%s] container on host [%s]", DINDPlane, containerName, cli.DaemonHost())
		dindContainer, err := cli.ContainerInspect(ctx, containerName)
		if err != nil {
			return "", fmt.Errorf("Failed to get the address of container [%s] on host [%s]: %v", containerName, cli.DaemonHost(), err)
		}
		dindIPAddress := dindContainer.NetworkSettings.IPAddress

		return dindIPAddress, nil
	}
	dindContainer, err := cli.ContainerInspect(ctx, containerName)
	if err != nil {
		return "", fmt.Errorf("Failed to get the address of container [%s] on host [%s]: %v", containerName, cli.DaemonHost(), err)
	}
	dindIPAddress := dindContainer.NetworkSettings.IPAddress
	logrus.Infof("[%s] container [%s] is already running on host[%s]", DINDPlane, containerName, cli.DaemonHost())
	return dindIPAddress, nil
}

func RmoveDindContainer(ctx context.Context, dindAddress string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithTimeout(60*time.Second))
	if err != nil {
		return err
	}
	containerName := fmt.Sprintf("%s-%s", DINDContainerPrefix, dindAddress)
	logrus.Infof("[%s] Removing dind container [%s] on host [%s]", DINDPlane, containerName, cli.DaemonHost())

	retry := 0
	var errInspecting error
	containerInspected := false

	for retry < 4 && errInspecting == nil && !containerInspected {
		ct, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		_, err = cli.ContainerInspect(ct, containerName)
		if err != nil {
			if !client.IsErrNotFound(err) {
				logrus.Infof("container %s not found while inspecting", containerName)
				return nil
			} else if IsTimeoutError(err) {
				logrus.Infof("timeout while inspecting container %s......retrying", containerName)
				retry++
				continue
			} else {
				errInspecting = err
				break
			}
		}
		containerInspected = true
	}

	if errInspecting != nil {
		return err
	} else if retry >= 4 {
		return fmt.Errorf("not able remove [%s] container after 4 retries....", containerName)
	}

	retry = 0
	var errRemoving error
	containerRemoved := false
	for retry < 4 && errRemoving == nil && !containerRemoved {
		ct, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := cli.ContainerRemove(ct, containerName, types.ContainerRemoveOptions{
			Force:         true,
			RemoveVolumes: true}); err != nil {
			if client.IsErrNotFound(err) {
				logrus.Infof("[remove/%s] Container doesn't exist on host [%s]", containerName, cli.DaemonHost())
				containerRemoved = true
				continue

			} else if IsTimeoutError(err) {
				logrus.Infof("[remove/%s] Timeout while removing Container on host [%s]...retrying ,err: %v", containerName, cli.DaemonHost(), err)
				retry++
				continue
			}
			errRemoving = fmt.Errorf("Failed to remove dind container [%s] on host [%s]: %v", containerName, cli.DaemonHost(), err)
			continue
		}
		containerRemoved = true
		logrus.Infof("[remove/%s] Container successfully removed  on host [%s]", containerName, cli.DaemonHost())
	}
	if containerRemoved {
		return nil
	} else if errRemoving != nil {
		return errRemoving
	} else if retry >= 4 {
		return fmt.Errorf("not able remove [%s] container after 4 retries....", containerName)
	}

	logrus.Infof("[%s] Successfully Removed dind container [%s] on host [%s]", DINDPlane, containerName, cli.DaemonHost())
	return nil
}

func IsTimeoutError(err error) bool {
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(strings.ToLower(err.Error()), "deadline")) {
		return true
	}
	return false
}
