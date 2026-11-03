"""Apply configured display identity in the selected target namespace."""
import ctypes,json,os,pathlib,subprocess
os.chdir("/")
p=json.loads(pathlib.Path("/run/cdm-ssh/fleet-identity/profile.json").read_text())
libc=ctypes.CDLL(None,use_errno=True)
def syscall(name,value):
 raw=value.encode()
 if getattr(libc,name)(raw,len(raw)):
  error=ctypes.get_errno();raise OSError(error,os.strerror(error))
if os.uname().nodename!=p["hostname"]:syscall("sethostname",p["hostname"])
if p.get("domainname"):syscall("setdomainname",p["domainname"])
base=pathlib.Path("/run/cdm-ssh/fleet-identity")
for source,destination in [("hostname","/etc/hostname"),("hostid","/etc/hostid"),("timezone","/etc/timezone"),("localtime","/etc/localtime"),("locale","/etc/locale.conf"),("locale","/etc/default/locale")]:
 data=(base/source).read_bytes();dest=pathlib.Path(destination)
 if not dest.exists() or dest.read_bytes()!=data:
  if dest.is_symlink():dest.unlink()
  dest.write_bytes(data)
  dest.chmod(0o644)
hosts=pathlib.Path("/etc/hosts")
lines=hosts.read_text().splitlines()
for i,line in enumerate(lines):
 parts=line.split()
 if parts and parts[0]==p["target_address"]:lines[i]=p["target_address"]+"\t"+p["hostname"]
new="\n".join(lines)+"\n"
if new!=hosts.read_text():hosts.write_text(new)
if pathlib.Path("/sys/class/net/eth0/address").read_text().strip().lower()!=p["mac_address"].lower():
 subprocess.run(["ip","link","set","dev","eth0","address",p["mac_address"]],check=True)
dest="/proc/sys/kernel/random/boot_id"
if pathlib.Path(dest).read_text().strip()!=p["boot_id"]:
 subprocess.run(["mount","--bind",str(base/"boot-id"),dest],check=True)
 subprocess.run(["mount","-o","remount,bind,ro",dest],check=True)
print("Live identity applied")
