# Continuous deployment (GitHub Actions → production VM)

On every push to `main` (e.g. when a PR is merged), the
`.github/workflows/deploy.yml` workflow SSHes into the production VM and
redeploys:

```
git fetch --all && git reset --hard origin/main && docker compose up -d --build
```

## One-time setup

### 1. On the VM — let Docker run without sudo and authorise a CI key

```bash
# Run Docker without sudo (so the non-interactive CI SSH session can use it)
sudo usermod -aG docker "$USER"
# log out and back in (or: newgrp docker) for the group to take effect

# Create a dedicated CI SSH key pair (no passphrase)
ssh-keygen -t ed25519 -f ~/ci_deploy_key -N "" -C "github-actions-deploy"
# Authorise it for logins to this VM
cat ~/ci_deploy_key.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
# Print the PRIVATE key — copy this into the GitHub secret SSH_PRIVATE_KEY
cat ~/ci_deploy_key
```

### 2. In the GitHub repo — add three secrets

Settings → Secrets and variables → Actions → New repository secret:

| Secret | Value |
|---|---|
| `VM_HOST` | the VM's external IP (e.g. `34.68.228.213`) |
| `VM_USER` | the VM login user (e.g. `krunal_wankhade1810`) |
| `SSH_PRIVATE_KEY` | the full contents of `~/ci_deploy_key` (the private key) |

### 3. Merge to `main`

The workflow runs on the merge commit and deploys automatically. You can also
trigger it manually from the repo's **Actions** tab (`Run workflow`).

## Notes
- Backend changes re-embed the NIST catalogue during the image build, so those
  deploys take ~5–10 minutes; frontend-only deploys are fast.
- The VM's external IP must stay the same, or update the `VM_HOST` secret.
- Delete `~/ci_deploy_key` from the VM if you ever rotate the CI key.
