apt update && apt upgrade -y
systemctl status portal
journalctl -u portal --since "1 hour ago" | tail -n 50
cd /opt/nexusai-inference
git log --oneline -5
docker compose ps
docker compose logs --tail=100 portal
systemctl reload nginx
nginx -t
certbot certificates
tail -f /var/log/nginx/portal.access.log
psql -h db-01 -U portal_ro -d portal -c 'select count(*) from orders;'
ufw status numbered
ss -tlnp
htop
free -m
df -h
apt list --installed 2>/dev/null | grep -i nginx
vi /etc/nginx/sites-available/portal.conf
systemctl restart portal
curl -sS http://127.0.0.1:3000/health
exit
