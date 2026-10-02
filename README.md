# Cryptanalyse d'implémentations RSA
Ceci est un projet d'initiation à la recherche qui a duré sur toutes l'année scolaire de ma premiere année du Master Cryptis.
Ce projet académique explore et implémente en Python deux attaques classiques contre le cryptosystème RSA : l'attaque de Wiener et l'attaque par oracle (PKCS#1 v1.5, algorithme de Bleichenbacher).

## Contenu du dépôt
* `Attaque_Wiener.py` : Implémentation de l'attaque de Wiener exploitant les vulnérabilités d'une clé privée trop petite grâce au développement en fractions continues.
* `Attaque_par_oracle.py` : Implémentation de l'attaque exploitant les failles du padding PKCS#1 v1.5.
* `Cryptanalyse d_impl mentations RSA.pdf` : Rapport complet détaillant l'étude théorique, les preuves mathématiques et les résultats d'exécution.
