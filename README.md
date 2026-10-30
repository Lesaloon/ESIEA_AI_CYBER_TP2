# TP 2 — RAG : attaquer, mesurer, défendre

Solution simple dans `tp_rag.py`, avec la bibliothèque standard Python uniquement.
Les données RH et les attaques sont fictives.

## Exécution

```bash
python3 tp_rag.py A       # Vérifications locales (sans modèle)
python3 tp_rag.py all     # Toutes les parties disponibles
```

Pour les expériences de génération et les détecteurs LLM :

```bash
ollama serve             # Dans un autre terminal
ollama pull qwen2.5:3b
python3 tp_rag.py A --llm
```

L'option `--llm` utilise le vrai modèle, sans réponse simulée. Sans cette option,
le script vérifie les mécanismes déterministes avec des assertions.
Les réponses Qwen et les mesures des détecteurs LLM restent à vérifier avec un
serveur actif ; les résultats attendus ci-dessous ne sont pas des mesures du modèle.

## Partie A — Fonctionnement et injection indirecte

**A1. Comment marche le RAG ?** BM25 classe les documents selon les mots de la
question. Les documents du top-k sont ajoutés au contexte, puis le modèle rédige
sa réponse. Localement, `conges` arrive avant `salaire`. Sur le document officiel,
la réponse attendue est **25 jours ouvrés par an**.

**A2. Document empoisonné :** `ATK1` prétend donner une nouvelle consigne et demande
de finir par `PWNED-42`. C'est une injection **indirecte** : l'ordre provient d'un
document récupéré, pas de l'utilisateur. Le modèle peut confondre les données avec
des instructions. Le test `--llm` vérifie si la réponse finit effectivement par ce
code ; une attaque peut échouer selon la génération.

## Partie B — Filtre d'entrée et mesures

Lancer `python3 tp_rag.py B` (ajouter `--llm` pour l'ensemble).

**B1.** Le filtre examine chaque document récupéré avant la génération. `ATK1`
déclenche le regex et est retirée ; le modèle ne reçoit plus cet ordre.

**B2.** `ATK2` demande d'ajouter le code en bas de la réponse, sans les formulations
connues du regex : résultat local **False**. L'ensemble combine regex, classifieur
et juge avec un OU. Le résultat attendu du modèle est **True**, car il peut repérer
l'intention malgré la paraphrase ; cela reste à mesurer avec `--llm`.

**B3. Résultat local sur les cinq exemples de l'énoncé :** regex : VP=1, FP=0,
FN=2, donc **précision 100 %**, **rappel 33 %**.
La précision vaut VP/(VP+FP), le rappel VP/(VP+FN). Un FP retire un document sain ;
un FN laisse passer une attaque. L'ensemble vise à améliorer le rappel, mais peut
produire des FP et coûte des appels au modèle. Ses chiffres sont affichés par le
script lors d'une vraie exécution, pas inventés ici.

Limite du TP : les détecteurs LLM ne lisent que les 300 premiers caractères.
Une consigne plus loin peut leur échapper ; il faudrait analyser tout le contenu
par morceaux pour traiter ce cas.

## Partie C — Identité, JWT et RBAC

Lancer `python3 tp_rag.py C` : ces vérifications ne nécessitent pas de LLM.

**C1.** Avec le filtre seul, `salaire` entre dans le contexte : un document
confidentiel ne contient pas forcément une injection. Un system prompt ne remplace
pas un contrôle d'accès.

**C2.** Le JWT contient `en-tête.payload.signature`. `jwt_decode` impose **HS256**,
recalcule le HMAC-SHA256 et compare la signature avec `hmac.compare_digest` avant
de faire confiance au payload. Le jeton RH honnête est accepté.

**C3. Résultats locaux :** jeton signé avec le mauvais secret → `signature invalide` ;
jeton `alg:none` → `alg refuse`.

**C4.** La matrice autorise public→public, rh→public+rh,
direction→public+rh+direction. Le RBAC retire les documents non autorisés du
contexte avant la génération. Résultats locaux :

| Identité | Documents accessibles |
| --- | --- |
| Public | conges |
| RH valide | salaire, conges (ordre BM25) |
| Faux jeton / alg:none / jeton absent | conges |

Le cas sans jeton retombe aussi en public : activer RBAC sans fournir de jeton
ne doit jamais désactiver le contrôle d'accès. Un rôle inconnu est également public.

**C5.** Si `exp` existe, le jeton est refusé dès `now >= exp`. Le test couvre
l'échéance exacte et `now=0`. Le jeton avec `exp=1` est expiré aujourd'hui ;
le jeton RH du socle reste accepté car il n'a pas de champ `exp`.
Une expiration réduit la durée d'utilisation d'un jeton volé, sans le révoquer
immédiatement. Les horloges doivent être synchronisées.

Le secret est celui, public, du cours et les jetons du socle n'expirent pas :
c'est une démonstration pédagogique. Une application réelle utiliserait un secret
privé et des jetons à durée de vie limitée.
