#!/usr/bin/python3
import os
import random
from sympy import isprime 
#===================================================
#Fonctions pour les calculs mathématiques de RSA
#===================================================

#fonction qui génere le nombre 
def generation_nombre(taille):
	
	while True:
		chiffres = [random.choice('123456789')]
		for i in range(taille-2):
			chiffres.append(random.choice('0123456789'))
		chiffres.append(random.choice('1379'))
		nombre=int("".join(chiffres))
		if isprime(nombre):
			return nombre
		else:
			while not isprime(nombre) :
				chiffres.pop(0)
				chiffres.pop()
				chiffres.append(random.choice('0123456789'))
				chiffres.append(random.choice('1379'))
				if chiffres[0]=='0':
					chiffres[0]=random.choice('123456789')
				nombre=int("".join(chiffres))
			return nombre
#On est a la deuxieme étape géneration des exposants et modules RSA	
def egcd(a, b):
	x,y, u,v = 0,1, 1,0
	while a != 0:
		q, r = b//a, b%a
		m, n = x-u*q, y-v*q
		b,a, x,y, u,v = a,r, u,v, m,n
	gcd = b
	return gcd, x, y
def modinv(a, m):
	gcd, x, y = egcd(a, m)
	if gcd != 1:
		return None
	return x % m
def generation_cles(taille):
	p=generation_nombre(taille)
	q=generation_nombre(taille)
	while q==p:
		q=generation_nombre(taille)
	n=p*q
	phi_n= (p-1)*(q-1)
	while True:
		e = random.randint(3, phi_n - 1)
		gcd, x, y = egcd(e, phi_n)
		if gcd == 1: # Si e est valide, on calcule d et on retourne les clés
			d = modinv(e, phi_n)
			return (n, e, d)

# Cette fonction représente L'oracle renvoie True si le message est PKCS-conforme, False sinon
def oracle(c_int):

    m_int = pow(c_int, d, n) #Déchiffrement RSA
    try:
        #Conversion de l'entier en blocs de K octets 
        m_bytes = m_int.to_bytes(k, byteorder='big')
    except OverflowError:
        #L'entier est trés grand pour ce module n
        return False
    
    # Vérification stricte du standard : 00 || 02 || Padding || 00 || Message
    if m_bytes[0] != 0x00 or m_bytes[1] != 0x02:
        return False
    try:
        #Recherche de l'octet séparateur nul 00
        idx = m_bytes.index(0x00, 2)
    except ValueError:
        #Pas d'octet séparateur trouvé
        return False
    if idx - 2 < 8: # Le padding doit faire au moins 8 octets
        return False
        
    return True #Si tout est valide la fonction retourne True 

#La fonction qui chiffre suivant le standard PKCS
def pkcs1_v15_chiffrement(message_clair: bytes, e: int, n: int) -> bytes:
    # Calcul de k : la taille du module n en octets
    k = (n.bit_length() + 7) // 8
    
    # Vérification de la taille limite du message
    if len(message_clair) > k - 11:
        raise ValueError(f"Message trop long. Max autorisé pour ce module : {k - 11} octets.")
    # Calcul de la longueur nécessaire pour le padding    
    ps_length = k - len(message_clair) - 3
    # Génération du padding aléatoire
    ps = bytearray()
    while len(ps) < ps_length:
        random_byte = os.urandom(1)
        if random_byte != b'\x00': # On rejette les octets nuls
            ps.extend(random_byte)
            
    # Assemblage du bloc formaté : 00 || 02 || Padding || 00 || Message
    eb = b'\x00\x02' + bytes(ps) + b'\x00' + message_clair
    #La conversion de la chaîne d'octets en entier
    x = int.from_bytes(eb, byteorder='big')
    
    #Le calcul RSA
    y = pow(x, e, n)
    #La conversion de l'entier en chaîne d'octets
    c = y.to_bytes(k, byteorder='big')
    
    return c #Nous retourne le chiffré 
# Cette fonction Caclule de la partie entiére superieure
def div_plafond(a, b): 
    return (a + b - 1) // b
#Cette fonction sert a la réduction des intervalles
def maj_intervalles(M_prec, s):
    M_nouv = []
    #On parcourt tous les intervalles restants 
    for a, b_val in M_prec:
        #Calcul des bornes de r: le nombre de tours
        r_min = div_plafond(a * s - 3 * B + 1, n)
        r_max = (b_val * s - 2 * B) // n
        #Calcul des nouvelles bornes [a,b] pour m_0
        for r in range(r_min, r_max + 1):
            borne_inf = max(a, div_plafond(2 * B + r * n, s))
            borne_sup = min(b_val, (3 * B - 1 + r * n) // s)
            # si le snouveaux intervalles forment une intersection valide avec l'ancien on les gardes
            if borne_inf <= borne_sup:
                M_nouv.append((borne_inf, borne_sup))
    return M_nouv # Nous retourne M_i
#=========================================================================================
#Début du Programme
#=========================================================================================
#Choix des clés 256 bits
n, e, d = generation_cles(39)

# k = taille du module en octets (ici 32 octets)
k = (n.bit_length() + 7) // 8
B = 2**(8 * (k - 2))


# --- Préparation de la cible ---
message_secret = b"Cryptis" # Notre message en clair
c_bytes = pkcs1_v15_chiffrement(message_secret, e, n) # Chiffrement
c = int.from_bytes(c_bytes, byteorder='big') # Texte chiffré intercepté
print("[*] Message cible chiffré. Lancement de l'attaque...")

# =====================================================================
# PHASE 1 : BLINDING (Masquage)
# =====================================================================
print("[*] Phase 1 : Masquage du message (Blinding)...")

#  On essaye d'abord s=1 pour verifier si notre c est déja conforme
if oracle(c):
    s0 = 1
    c0 = c
    print("    -> Le cryptogramme est déjà conforme (s0 = 1).")
else:
    print("    -> Cryptogramme non conforme. Recherche d'un masque s0 aléatoire...")
    while True:
        # Tirage d'un s0 aléatoire entre 2 et n-1
        s0 = random.randint(2, n - 1)
        c0 = (c * pow(s0, e, n)) % n
        
        # On interroge l'oracle pour ce s_0 random
        if oracle(c0):
            print(f"    -> Masque valide trouvé ! s0 = {s0}")
            break

# =====================================================================
# PHASE 2.a : RECHERCHE DU PREMIER MULTIPLICATEUR (s1)
# =====================================================================
print("[*] Phase 2.a : Recherche de s1...")
s = n // (3 * B) #Le s est surement superieur a n/3B  
#On continue à incrémenter le s jusqu'à ce que l'oracle retourne true 
while not oracle((c0 * pow(s, e, n)) % n):
    s += 1
print(f"[+] s1 trouvé : {s}")
M = [(2 * B, 3 * B - 1)]# Initialisation de M_0
M = maj_intervalles(M, s) #On met à jour l'intervalle gràce au s1 trouvé

# =====================================================================
# PHASES 2 & 3 : RÉDUCTION DES INTERVALLES
# =====================================================================
print("[*] Phase 2.b/c & 3 : Réduction itérative des intervalles...")
iteration = 1

while True:
    # Condition d'arret si l'intervalle est réduit a un seul élément
    if len(M) == 1 and M[0][0] == M[0][1]:
        x = M[0][0] # On a trouvé le message masqué (m0)
        
        # =====================================================================
        # PHASE 4 : UNBLINDING (Démasquage final)
        # =====================================================================
        # Calcul de l'inverse modulaire de s0 (s0^-1). 
        s0_inv = pow(s0, -1, n) 
        
        # Le vrai message : m = a * s0^-1 mod n
        m_trouve = (x * s0_inv) % n 
        
        # Extraction du texte en clair
        m_bytes = m_trouve.to_bytes(k, byteorder='big')
        idx = m_bytes.index(0x00, 2)
        print(f"SUCCÈS ! Message décodé : {m_bytes[idx+1:].decode('utf-8')}")
        break
    # =====================================================================
    # PHASE 2.b : Recherche avec plusieurs intervalles
    # =====================================================================
    if len(M) > 1: #Ici on continue le balayage en essayant plus de valeurs pour s
        s += 1
        while not oracle((c0 * pow(s, e, n)) % n): 
            s += 1
    # =====================================================================
    # PHASE 2.c : Recherche avec un intervalle unique (Accélération)
    # =====================================================================        
    elif len(M) == 1:
        a_val, b_val = M[0]
        r = div_plafond(2 * (b_val * s - 2 * B), n)#Calcul de la borne inf pour r
        trouve = False
        while not trouve:
            #Calcul des bornes pour s
            s_min = div_plafond(2 * B + r * n, b_val)
            s_max = (3 * B - 1 + r * n) // a_val
            #On cherche la conformité dans cet intervalle uniquement
            for s_test in range(s_min, s_max + 1):
                if oracle((c0 * pow(s_test, e, n)) % n):
                    s = s_test
                    trouve = True
                    break #Si le s trouvé on sort de la boucle
            r += 1 #On passe au tour suivant 
            
    M = maj_intervalles(M, s) # La mise a jour de l'intervalle avec le s trouvé
    iteration += 1
print(f"    -> Itération {iteration}")