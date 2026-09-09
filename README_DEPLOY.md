# Vault Server - Deploy lên Render.com (FREE)

## 5 Bước deploy

### 1. Tạo GitHub repo
```bash
# Tren may co folder nay
git init
git add .
git commit -m "init vault server"
# Tren GitHub tao repo "vault-may-chu" (public)
git remote add origin https://github.com/MINH-USERNAME/vault-may-chu.git
git branch -M main
git push -u origin main
```

### 2. Vào Render Dashboard
https://dashboard.render.com

### 3. Tạo Web Service
- Click **"New +"** (góc phải trên) → **"Web Service"** (ảnh dashboard mày đang thấy)
- Click **"Connect GitHub"** (nếu chưa connect)
- Chọn repo `vault-may-chu`
- Click **"Connect"**

### 4. Cấu hình (giữ mặc định + đổi 2 thứ)
- **Name**: `vault-may-chu` (tùy ý)
- **Region**: `Oregon` (gần VN nhất trong free)
- **Plan**: **Free** (0$/tháng, sleep sau 15p không request)
- **Advanced** → Add **Environment Variables**:
  - `VAULT_ADMIN_TOKEN` = mã bí mật dài (VD: `vault-2024-secret-xyz-abc-12345-very-long`)
  - `VAULT_SESSION_TTL` = `3600`
- **Advanced** → Add **Disk**:
  - Name: `vault-data`
  - Mount Path: `/data`
  - Size: `1 GB` (free)
- Click **"Create Web Service"**

### 5. Đợi deploy (3-5 phút)
Sau khi deploy xong, Render cho URL dạng:
```
https://vault-may-chu.onrender.com
```
Copy URL này, mở admin_app → bấm "Cấp User" → sửa Server URL = URL này → gán user.

## Lưu ý
- **Free plan sleep** sau 15p không có request. Lần đầu user login sẽ chờ ~30s để server wake up.
- **Dùng nhiều user** → nên upgrade lên Starter plan ($7/tháng, không sleep) nếu mày muốn 24/7.
- **Bảo mật**: Token admin KHÔNG share cho user. Token này chỉ admin app dùng để cấp user.
- **Backup**: Vào Render dashboard → Disks → Download để backup users.json + vaults/.

## ⚠️ QUAN TRỌNG: Thêm GITHUB_TOKEN trên Render

Vì Render Free không có persistent disk, server lưu data vào GitHub repo. Cần set `GITHUB_TOKEN` trên Render:

1. Vào https://github.com/settings/tokens → dùng token `render-deploy` đã tạo
2. Quay Render Dashboard → Service `vault-may-chu` → **Environment** tab
3. Bấm **"Add Environment Variable"**:
   - **Key**: `GITHUB_TOKEN`
   - **Value**: dán token `render-deploy` (loại Fine-grained, có quyền Contents: Read and write trên repo `vault-may-chu`)
4. Bấm **Save** → Render tự re-deploy
5. Đợi 1-2 phút → check Logs: thấy `[storage] Using GitHub repo for data persistence` là OK
