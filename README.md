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