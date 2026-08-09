import io, json, os, shutil, subprocess, tempfile, time
from pathlib import Path
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]

def test_info_target_contract():
    info=(ROOT/"spk/INFO").read_text()
    for x in ['package="VeraMesh"','version="0.1.0-0003"','arch="armada38x"','os_min_ver="7.2-72806"','install_dep_packages="Node.js_v22"','ctl_stop="yes"','dsmuidir="ui"','dsmappname="com.vera.Mesh"']:
        assert x in info
    assert "python" not in info.lower()

def test_icons_are_vera_and_correct_dimensions():
    import hashlib, io
    from PIL import Image
    import sys
    sys.path.insert(0,str(ROOT/"tools"))
    from build_spk import derived_icon_bytes
    p=ROOT/"spk/PACKAGE_ICON.PNG"
    assert hashlib.sha256(p.read_bytes()).hexdigest()=="7a7e58574f82b16f9522c2b61456ac84b46f33b8a7c75c24e02f3db7e897b59a"
    with Image.open(p) as im: assert im.size==(64,64)
    b=derived_icon_bytes(p.read_bytes(),256)
    with Image.open(io.BytesIO(b)) as im: assert im.size==(256,256)

def test_ui_config_targets_static_dsm_surface():
    cfg=json.loads((ROOT/"payload/ui/config").read_text())
    app=cfg[".url"]["com.vera.Mesh"]
    assert app["url"]=="3rdparty/VeraMesh/index.html"
    assert app["icon"]=="images/app_{0}.png"

def test_node_daemon_safe_idle_lifecycle():
    node=os.environ.get("NODE_BIN","node")
    with tempfile.TemporaryDirectory() as td:
        var=Path(td)/"var"; ui=Path(td)/"ui"; ui.mkdir(parents=True)
        env={**os.environ,"VERAMESH_VAR":str(var),"VERAMESH_UI_DIR":str(ui)}
        p=subprocess.Popen([node,str(ROOT/"payload/app/veramesh_daemon.js")],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        state_file=var/"state/runtime.json"
        deadline=time.time()+5
        while time.time()<deadline and not state_file.exists(): time.sleep(.05)
        assert state_file.exists()
        s=json.loads(state_file.read_text())
        assert s["serviceState"]=="RUNNING"
        assert s["meshState"]=="SAFE_IDLE_UNPAIRED"
        assert s["pairingEnabled"] is False and s["transportEnabled"] is False and s["listener"] is None
        assert s["pid"]==p.pid
        p.terminate(); p.wait(timeout=5)
        s2=json.loads(state_file.read_text())
        assert s2["serviceState"]=="STOPPED"
        u=json.loads((ui/"runtime-status.json").read_text())
        assert u["serviceState"]=="STOPPED"

def test_no_python_systemd_or_network_server_in_runtime_surface():
    alltext="\n".join([
        (ROOT/"spk/scripts/start-stop-status").read_text(),
        (ROOT/"payload/app/veramesh_daemon.js").read_text(),
        (ROOT/"spk/INFO").read_text(),
    ]).lower()
    assert "python3.11" not in alltext
    assert "synosystemctl" not in alltext
    assert "createserver" not in alltext
    assert ".listen(" not in alltext


def test_start_stop_status_happy_path_against_real_node_process():
    node=shutil.which("node")
    assert node
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        target=td/"target"; var=td/"var"
        (target/"app").mkdir(parents=True)
        (target/"ui").mkdir(parents=True)
        shutil.copy2(ROOT/"payload/app/veramesh_daemon.js", target/"app/veramesh_daemon.js")
        shutil.copy2(ROOT/"payload/ui/runtime-status.json", target/"ui/runtime-status.json")
        ctl=td/"start-stop-status"; shutil.copy2(ROOT/"spk/scripts/start-stop-status",ctl); ctl.chmod(0o755)
        post=td/"postinst"; shutil.copy2(ROOT/"spk/scripts/postinst",post); post.chmod(0o755)
        env={**os.environ,"SYNOPKG_PKGDEST":str(target),"SYNOPKG_PKGVAR":str(var),"VERAMESH_NODE_BIN":node}
        assert subprocess.run([str(post)],env=env).returncode==0
        assert subprocess.run([str(ctl),"status"],env=env).returncode==3
        assert subprocess.run([str(ctl),"prestart"],env=env).returncode==0
        assert subprocess.run([str(ctl),"start"],env=env).returncode==0
        assert subprocess.run([str(ctl),"status"],env=env).returncode==0
        running=json.loads((var/"state/runtime.json").read_text())
        assert running["serviceState"]=="RUNNING"
        assert running["meshState"]=="SAFE_IDLE_UNPAIRED"
        assert running["listener"] is None
        assert subprocess.run([str(ctl),"stop"],env=env).returncode==0
        assert subprocess.run([str(ctl),"status"],env=env).returncode==3
        stopped=json.loads((var/"state/runtime.json").read_text())
        assert stopped["serviceState"]=="STOPPED"
