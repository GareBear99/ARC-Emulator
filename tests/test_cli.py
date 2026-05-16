from arc_emulator.cli import main

def test_smoke(capsys):
    main(['smoke'])
    out=capsys.readouterr().out
    assert 'arc-emulator smoke passed' in out
