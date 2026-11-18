import pytest

from security.file_upload import (
    check_magic,
    safe_filename,
    validate_upload,
    svg_safe,
    max_size_ok
)


def test_jpeg_magic():
    assert check_magic(b'\xff\xd8\xff\xe0', 'jpg') is True

def test_png_magic():
    assert check_magic(b'\x89PNG\r\n\x1a\n', 'png') is True

def test_polyglot():
    assert check_magic(b'\xff\xd8\xff<?php', 'jpg') is False

def test_safe_traversal():
    name = safe_filename('../../etc/passwd')
    assert '..' not in name

def test_safe_null():
    assert chr(0) not in safe_filename('a' + chr(0) + '.jpg')

def test_safe_absolute():
    assert '/' not in safe_filename('/tmp/a.jpg')

def test_svg_bad():
    assert svg_safe('<svg onload=alert(1)>') is False

def test_svg_ok():
    assert svg_safe('<svg><circle/></svg>') is True

def test_too_big():
    assert max_size_ok({'size': 10**9}) is False

def test_upload_ok():
    meta = {'filename': 'a.jpg', 'content_type': 'image/jpeg', 'size': 100}
    assert validate_upload(meta, b'\xff\xd8\xff\xe0') is True

def test_mime_mismatch():
    meta = {'filename': 'a.jpg', 'content_type': 'text/html', 'size': 100}
    assert validate_upload(meta, b'\xff\xd8\xff\xe0') is False

def test_symlink():
    meta = {'filename': 'a.jpg', 'content_type': 'image/jpeg', 'size': 100, 'symlink': True}
    assert validate_upload(meta, b'\xff\xd8\xff\xe0') is False

def test_double_ext():
    assert safe_filename('a.php.jpg').endswith('.jpg')

def test_empty_magic():
    assert check_magic(b'', 'jpg') is False

def test_empty_upload():
    assert validate_upload({}, b'') is False
