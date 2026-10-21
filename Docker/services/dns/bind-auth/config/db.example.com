$TTL 604800
@       IN      SOA     ns1.example.com. admin.example.com. (
                              2024010101    ; Serial
                              604800        ; Refresh
                              86400         ; Retry
                              2419200       ; Expire
                              604800 )      ; Negative Cache TTL
@       IN      NS      ns1.example.com.
ns1     IN      A       127.0.0.1
@       IN      A       93.184.216.34
www     IN      A       93.184.216.34
