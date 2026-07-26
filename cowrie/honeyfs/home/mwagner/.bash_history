ssh gpu01
sudo -i
cd /opt/nexusai-inference && git log --oneline -3
sudo systemctl status portal nginx
sudo tail -n 100 /var/log/nginx/portal.error.log
sudo -u postgres psql -h db-01 -c '\l'
htop
df -h
sudo apt update
logout
