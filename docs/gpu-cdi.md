# GPU CDI 准备

目标容器使用 Docker CDI 设备 `nvidia.com/gpu=all`。这表示容器可以看到主机上的全部 GPU，但不会修改 GPU 的计算模式，也不会停止其他任务。Compose 只把设备交给 `target`，网关、DNS 和 canary 不使用 GPU。

## 每台服务器准备

先确认宿主驱动正常：

```bash
nvidia-smi --query-gpu=index,name,compute_mode --format=csv,noheader
```

然后按 NVIDIA 官方仓库安装基础工具包。以下命令只安装 CDI 所需工具，不配置 Docker runtime：

```bash
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#^deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#' \
  > /etc/apt/sources.list.d/nvidia-container-toolkit.list
apt-get update
apt-get install -y nvidia-container-toolkit-base
```

确认 CDI 设备存在：

```bash
nvidia-ctk cdi list
```

输出必须包含 `nvidia.com/gpu=all`。如果没有，先检查驱动和 CDI 生成服务；不要启动沙箱。

## 独立验收

在不接入本项目网络的临时容器中验证全部 GPU：

```bash
docker run --rm --network none \
  --device nvidia.com/gpu=all \
  cdm-base-ubuntu:24.04-sha256-52df9b1e \
  nvidia-smi --query-gpu=index,name,compute_mode --format=csv,noheader
```

行数应等于主机 GPU 数量，`compute_mode` 不应被改成 `Exclusive`。随后运行 `sudo bin/sandboxctl start`；启动前控制器会再次检查 CDI，缺失时保持停止。

本项目不执行 `nvidia-ctk runtime configure`，不改 `/etc/docker/daemon.json`，也不自动重启 Docker。这样不会影响同一宿主上的其他容器；如果某台服务器的 Docker 版本不支持 CDI，应先单独评估，不能为了沙箱重启共享 Docker 服务。

官方依据：[NVIDIA Container Toolkit 安装指南](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)、[CDI 文档](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/cdi-support.html)。
