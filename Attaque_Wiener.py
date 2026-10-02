#!/usr/bin/python3
import math
import time
import sys

def egcd(a, b): #Algorithme d'euclide étendu
	x,y, u,v = 0,1, 1,0
	while a != 0:
		q, r = b//a, b%a
		m, n = x-u*q, y-v*q
		b,a, x,y, u,v = a,r, u,v, m,n
	gcd = b
	return gcd, x, y #Nous retourne le pgcd ainsi que les coeeficients de Bezout 

def modinv(a, m):# calcul de l'inverse modulaire
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # L'inverse n'existe pas
    return x % m

def lpowmod(x, y, n):#x^y mod n
	result=1
	while y>0:
		if y&1>0:
			result = (result*x)%n
		y>>=1
		x = (x*x)%n
	return result
#les fonctions e dessus sont des fonctions fournies par Mr Bonnefoi pour un projet donc je les ai utilisé ici pour l'attaque naive et celle de Wiener
# Les deux fonctions qui suiveront seront utilisées pour l'attaque naive 
def Factorisation(n): # Cette fonction factorise n par la méthode naive 
        if n%2==0:
            return 2, n/2
        for i in range(3 , math.isqrt(n)+1 , 2): # ça va jusqu'a racine(n)+1 par un pas de 2 a partir de 3 pour eviter les multiples de 2
            if n%i==0:
                return i, n//i
        return None, None 

def attaque_naive(n,e,c): # Fonction de l'attaque naive
    print(f"Début de l'attaque naive sur ({n, e})")
    start_time=time.time() 
    p,q= Factorisation(n) # Fait appel a la fonction de factorisation
    if p is None: 
        print("Les valeurs introduites ne peuvent pas représenter un systéme RSA") # si elle affiche cela il y a des erreurs dans les valeurs choisis 
    else:
        end_time=time.time()
        temps_calcul=end_time-start_time #pour voir combien a durer l'attaque naive
        print(f"Factorisation réussie p={p}, q={q}")
        phi_n=(p-1)*(q-1)
        print(f" La Factorisation a pris {temps_calcul:.3f} secondes")
        try:
            d=modinv(e,phi_n)
            m=lpowmod(c,d,n)
            return p,q,d,m
        except:
            print("e ne peut pas etre la clé publique de ce systéme") #c'est a dire que e n'est pas premier avec e donc erreur dans les valeurs choisis
            return None
#Les 4 fonctions qui suiveront seront utilisées pour l'attaque de Wiener
def fractions_continues(e,n): # Calcul des fractions continues  
    quotients=[]
    num, denom =e,n
    while denom!=0:
        q = num // denom
        r = num % denom
        quotients.append(q)
        num,denom=denom,r
    return quotients # Nous renvoie une liste avec les q_i

def convergentes(quotients):#Calcul des convergentes
    k=[]
    d=[]# initialisations des d_i et k_i
    if len(quotients)==0:# au cas ou la liste quotients est vide ce aui n'arrivera pas si les valeurs choisis sont acceptables pour un systeme RSA 
        return[]
    k.append(quotients[0])
    d.append(1)# On initialise k_0 et d_0
    if len(quotients)==1:
        return list(zip(k,d))# Pareil on est pas censé arrivé la si le systeme a des valeurs convenables
    k.append(quotients[1]*quotients[0]+1)
    d.append(quotients[1])
    for i in range (2,len(quotients)):# Cette boucle continue a calculer les convergentes suivant le projet
        val_k = quotients[i] * k[i-1] + k[i-2]
        val_d = quotients[i] * d[i-1] + d[i-2]
        k.append(val_k)
        d.append(val_d)
    return zip(k,d)# nous retourne une liste de convergentes 

def resolution_quadratique(a,b,c): # cette foction est specialement  pour l'étape 3 de l'algorithme de Wiener pour calculer p et q 
    delta = b*b -4*a*c
    if delta<0:
        return None
    sqrt_delta=math.isqrt(delta)
    if sqrt_delta*sqrt_delta != delta: # Verifie que le descriminant est un carré parfait
        return None
    x1=(-b+sqrt_delta)//(2*a)
    x2=(-b-sqrt_delta)//(2*a)
    return x1,x2

def Attaque_Wiener(n,e,c):# et celle ci est l'attaque de Wiener 
    print(f"Début de l'attaque Wiener sur (n,e)={n,e}")
    start_time=time.time()
    Q=fractions_continues(e,n)
    C=convergentes(Q)
    for i ,j in C:
        if i== 0: #pour eviter la division par 0 au debut 
            continue
        if (e*j-1) % i !=0: #Si phi n'est pas un entier on passe puisque il n'est pas acceptable 
            continue
        phi_valide=(e*j-1)//i
        racines=resolution_quadratique(1,-n+phi_valide-1,n)
        try:
            if racines:
                p,q=racines
                if p*q==n:
                    end_time=time.time()
                    temps_calcul=end_time-start_time
                    print(f"Attaque de Wiener réussie ")
                    print(f"Temps de résolution {temps_calcul:.10f} ")
                    m=lpowmod(c,j,n)
                    return p,q,j,m
        except:
            print("Echec de l'attaque de wiener d n'est pas aseez petit")    


# Ici c'est l'application on a chosi des valeurs adaptés pour que 'attaque naive ne prenne pas beaucoup de temps et qu'on puisse l'appliquer sur nos PC
n = 2250001506000001003
e=556931065099009901 # son inverse d est 101 donc il est assez petit pour qu'on puisse appliquer l'attaque de Wiener
c = lpowmod(12345, e, n)# Calcul d'un texte chiffré a partir d'un message clair 12345
#Démarrage de l'attaque naive
print("-----------------------Attaque naive-------------")
p,q,d,m=attaque_naive(n,e,c)
phi_n=(p-1)*(q-1)
print(f"La fonction indicatrice d'euler est egale a {phi_n}")

print(f"La clé privé est trouvé d={d}")
print(f"Le message est retrouver {m}")
print("-----------------Fin de l'attaque naive---------------------")
# Démarrage Attaque de wiener
print("-----------------------Attaque de Wiener--------------------------")
p1,q1,d1,m1=Attaque_Wiener(n,e,c)
phi_n1=(p1-1)*(q1-1)
print(f"La fonction indicatrice d'euler est egale a {phi_n1}")

print(f"La clé privé est trouvé d={d1}")
print(f"Le message est retrouver {m1}")
print("-----------------------Fin Attaque de Wiener--------------------------")
