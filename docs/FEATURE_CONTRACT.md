# Feature Contract

Le modele de production utilise exactement ces 12 features, dans cet ordre :

| Feature | Source EVE | Unite |
|---|---|---|
| destination_port | dest_port | port |
| flow_duration | flow.start/end | microsecondes |
| total_fwd_packets | flow.pkts_toserver | paquets |
| total_fwd_bytes | flow.bytes_toserver | octets |
| flow_bytes_per_sec | bytes totaux / duree | octets/s |
| flow_packets_per_sec | paquets totaux / duree | paquets/s |
| fwd_packets_per_sec | paquets serveur / duree | paquets/s |
| bwd_packets_per_sec | paquets client / duree | paquets/s |
| avg_packet_size | bytes totaux / paquets totaux | octets |
| fin_flag_present | tcp.fin | binaire |
| psh_flag_present | tcp.psh | binaire |
| ack_flag_present | tcp.ack | binaire |

La definition executable est dans `src/features/feature_extraction.py`.
Toute modification de l'ordre exige de regenerer scaler, label encoder et
modeles. Une prediction n'est pas executee si l'ordre du vecteur diverge.
