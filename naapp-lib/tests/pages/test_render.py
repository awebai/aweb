from aweb_naapp.pages.render import page_shell


def test_shell_enforces_security_and_keeps_host_chrome_separate():
    shell = page_shell(script_path='/assets/gallery.js', asset_origin='https://assets.example')
    csp = shell.headers['Content-Security-Policy']
    assert "require-trusted-types-for 'script'" in csp
    assert 'trusted-types dompurify' in csp
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert "frame-ancestors 'none'" in csp
    assert shell.headers['Referrer-Policy'] == 'no-referrer'
    assert shell.headers['X-Content-Type-Options'] == 'nosniff'
    assert shell.headers['Cache-Control'] == 'no-store'
    assert 'https://assets.example' in csp
    assert '<div id="page" tabindex="-1"></div>' in shell.html
    assert shell.html.index('id="identity"') < shell.html.index('id="page"')
    assert shell.html.index('id="destinations"') > shell.html.index('id="page"')


def test_shell_rejects_untrusted_script_or_asset_origins():
    import pytest
    for script in ['//evil.example/x.js', '/x.js?token=secret', 'javascript:alert(1)']:
        with pytest.raises(ValueError):
            page_shell(script_path=script, asset_origin='https://assets.example')
    for origin in ['https://assets.example/path', 'https://a.example\nscript-src *', 'javascript:x']:
        with pytest.raises(ValueError):
            page_shell(script_path='/assets/gallery.js', asset_origin=origin)
