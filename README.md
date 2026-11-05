# TEAM DƯƠNG Auth API

Backend đăng nhập riêng cho extension. Dùng PostgreSQL, bcrypt (hash mật khẩu) và JWT.

## Deploy Render
1. Đẩy thư mục này lên một GitHub repository riêng.
2. Tạo Render Web Service từ repo đó: Build Command `npm install`, Start Command `npm start`.
3. Gắn PostgreSQL database và đặt `DATABASE_URL` bằng Internal Database URL.
4. Environment variables: `JWT_SECRET` (chuỗi ngẫu nhiên dài tối thiểu 32 ký tự), `ADMIN_USERNAME=admin`, `ADMIN_PASSWORD` (mật khẩu mạnh tối thiểu 12 ký tự), `ADMIN_DISPLAY_NAME=TEAM DUONG ADMIN`.
5. Deploy. Kiểm tra `https://TEN-SERVICE.onrender.com/health`.
6. Trong extension, mở Options và thay URL API nếu service không dùng `https://teamduong-auth-api.onrender.com`.

## API
- `POST /api/auth/login` body `{ "identifier": "admin", "password": "..." }`
- `GET /api/admin/users` (Admin)
- `PUT /api/admin/users/:id` (Admin; tạo/cập nhật)
- `PATCH /api/admin/users/:id/status` (Admin)
- `PATCH /api/admin/users/:id/online` (đăng nhập hiện tại hoặc Admin)
- `DELETE /api/admin/users/:id` (Admin)

Mật khẩu chỉ được lưu dưới dạng bcrypt hash. Không sử dụng mật khẩu mẫu `123` trên hệ thống thật.

**Lưu ý tương thích:** dữ liệu người dùng cũ trong Firebase không tự động chuyển sang PostgreSQL; tạo lại thành viên qua trang Quản lý người dùng. Các collection Firebase khác (mẫu tin, chiến dịch, dữ liệu liên hệ...) và logic gửi tin Zalo được giữ nguyên trong gói extension này.
