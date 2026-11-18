# pairwise-file-upload

头像上传接口一开放，文件校验就只剩扩展名：只查 .jpg/.png 后缀，Content-Type 完全信客户端；magic bytes 不校验，polyglot JPEG+PHP 能同时通过图片和脚本解析；双扩展名和末尾空字节能绕过黑名单；文件名直接拼进上传目录，../ 可以写到任意路径；同名文件默认覆盖；SVG 不过滤，内嵌 onload 直接 XSS；超大图片解压后内存爆掉；EXIF 里的注释和 ICC 数据原样保留；上传目录可执行；软链接能指向系统文件；文件大小只查请求头；文件名冲突随机数可预测；Content-Disposition 用用户文件名；图片重编码关闭；临时文件不清理。security/file_upload.py 是核心，tests/test_file_upload.py 15个红。要修的是：magic bytes；扩展名白名单；双扩展与空字节；路径归一；不覆盖；SVG 清洗；解压尺寸限制；元数据剥离；目录权限；拒绝软链接；真实大小；安全随机名；响应头；服务端重编码；临时文件清理。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
