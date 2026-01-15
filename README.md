```markdown
# Evenster — skeleton sécurisé (backend + frontend)

Petit projet d'exemple pour démontrer une application "Evenster" (gestion d'événements) :
- backend: Java Spring Boot (REST API) + sécurité (JWT / BCrypt / CORS / headers de sécurité / rate-limit prototype)
- frontend: React + Vite + TypeScript (SPA) consommant l'API

Commandes rapides :

Backend
- cd backend
- mvn clean package
- mvn spring-boot:run
- L'API écoute sur http://localhost:8080

Frontend
- cd frontend
- npm install
- npm run dev
- Le dev server proxy les requêtes /api vers http://localhost:8080

Notes
- Stockage en mémoire pour prototype. Remplacez par une vraie BDD pour production.
- Secret JWT actuel dans application.yml pour développement ; en production utilisez une variable d'environnement.
- Si vous souhaitez les tokens en httpOnly cookies, demandez l'adaptation (CSRF à réactiver).
```
# Résumé du déploiement WAR sur WildFly
Étape 1 — Copier le WAR depuis Windows vers la VM (SCP)

scp -i "C:\Users\Administrator\Downloads\ubuntu_key.pem" `
"C:\Users\Administrator\Desktop\Projet-AppSec\wildfly-security-project\backend\target\evenster-backend-0.0.1-SNAPSHOT.war" `
taher@20.199.75.4:/home/taher/


Le WAR sera copié dans /home/taher/ sur la VM.

Étape 2 — Vérifier le fichier sur la VM

Connecté en SSH à la VM :

ls ~


Tu dois voir :

evenster-backend-0.0.1-SNAPSHOT.war

Étape 3 — Déployer le WAR sur WildFly

Localiser le dossier WildFly:

/opt/wildfly


Si incertain :

find / -type d -name wildfly 2>/dev/null


Définir la variable d’environnement WildFly :

export WILDFLY_HOME=/opt/wildfly


Copier le WAR dans le dossier de déploiement :

cp ~/evenster-backend-0.0.1-SNAPSHOT.war $WILDFLY_HOME/standalone/deployments/

Étape 4 — Démarrer WildFly

Exécuter :

$WILDFLY_HOME/bin/standalone.sh


Vérification dans les logs :

Deployed "evenster-backend-0.0.1-SNAPSHOT.war"


Cela confirme que le déploiement a réussi.