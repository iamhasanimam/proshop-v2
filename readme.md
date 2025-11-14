# Deployment of Ecommerce App on AWS Cloud with ECS CICD and Observability

![alt text](ECS-Architecture.png)

## Phase 1: Vision, Repository Structure & Branching Strategy

### Goal
Establish a clean, maintainable codebase foundation ready for infrastructure automation and CI/CD pipelines.

### Why This Matters
- Clear directory structure simplifies Docker builds, ECS task definitions, and GitHub Actions workflows
- Proper branching strategy prevents unstable code from reaching production
- Organized structure makes onboarding and debugging significantly easier

### Tasks

#### Repository Structure
```
proshop-v2/
├── frontend/           # React application
│   ├── public/
│   ├── src/
│   ├── dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── package-lock.json
├── backend/            # Express server with MongoDB
│   └── server.js
├── gateway/            # Nginx reverse-proxy
│   ├── dockerfile
│   └── nginx.conf
├── dockerfile          # Backend Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .gitignore
├── package.json
└── package-lock.json
```

#### Branching Strategy
- `main` → production-ready code only
- `dev` → development and staging experiments
- Feature branches → merge to `dev` first, then `main` after testing

#### Initial Setup
- Add comprehensive `.gitignore` for `node_modules`, `build`, `.env`, OS files
- Document structure in root README.md
- Set up branch protection rules for `main`

---

## Phase 2: Backend Dockerization (Node.js/Express)

### Goal
Create a lean, reproducible Docker image for the backend service that can run consistently across local, staging, and production environments.

### Why This Matters
- Identical image runs in development, ECS Fargate, and potential future Kubernetes clusters
- Multi-stage builds significantly reduce final image size
- Removes development dependencies from production runtime

### Tasks

#### Backend Dockerfile
Located at root: `dockerfile` (for backend)

```dockerfile
# Stage 1: Install dependencies
FROM node:20-alpine AS deps
WORKDIR /app
# Copy root package files
COPY package*.json ./
# Install only production deps
RUN npm ci --omit=dev

# Stage 2: Runtime
FROM node:20-alpine AS runner
WORKDIR /app
# Optional but nice
ENV NODE_ENV=production
ENV PORT=5000

# Copy installed node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules
# Copy backend folder into /app/backend
COPY ./backend ./backend

# Create uploads dir inside container and make a symlink with /app/uploads
RUN mkdir -p /var/data/uploads \
    && ln -s /var/data/uploads /app/uploads

EXPOSE 5000
CMD ["node", "backend/server.js"]
```

#### Verification Steps
- Confirm `backend/server.js` listens on `process.env.PORT || 5000`
- Verify upload path is configurable or defaults to `/var/data/uploads`
- Test build locally: `docker build -t lauv-backend:test .`
- Run container: `docker run -p 5000:5000 lauv-backend:test`

---

## Phase 3: Frontend Dockerization (React + Nginx)

### Goal
Build optimized static React assets and serve them efficiently using Nginx.

### Why This Matters
- React production builds are just static HTML/CSS/JS files
- Nginx is extremely fast, lightweight, and industry-standard for static content
- Separates build-time from runtime concerns

### Tasks

#### Frontend Dockerfile
Located at `frontend/dockerfile`

```dockerfile
# Stage 1: Build React application
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

#### Frontend Nginx Configuration
Located at `frontend/nginx.conf`

```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri /index.html;
    }
}
```

#### Key Features
- SPA routing: all routes fall back to `index.html` for React Router
- Efficient static file serving
- No unnecessary redirects

---

## Phase 4: Gateway Dockerization (Central Nginx Entry Point)

### Goal
Deploy a single Nginx gateway as the entry point for all traffic, routing requests to appropriate backend services.

### Why This Matters
- Centralized control for routing, headers, logging, and security
- Clean separation between public-facing gateway and internal services
- Foundation for advanced features: rate limiting, request IDs, custom error pages
- Simplifies future microservices architecture

### Tasks

#### Gateway Dockerfile
Located at `gateway/dockerfile`

```dockerfile
FROM nginx:alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

#### Gateway Nginx Configuration
Located at `gateway/nginx.conf`

```nginx
upstream frontend_upstream {
    server frontend-service:80;
}

upstream backend_upstream {
    server backend-service:5000;
}

server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://frontend_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://backend_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /uploads/ {
        proxy_pass http://backend_upstream;
    }
}
```

#### Routing Logic
- `/` → frontend service (React app)
- `/api/` → backend service (Express API)
- `/uploads/` → backend service (static file serving)

---

## Phase 5: Local Integration with Docker Compose

### Goal
Validate entire architecture locally before deploying to AWS.

### Why This Matters
- Local debugging is 10x faster than debugging in ECS
- Confirms Dockerfiles, networking, and routing work together correctly
- Catches configuration issues early
- Provides development environment parity with production

### Tasks

#### Docker Compose Configuration
Located at root: `docker-compose.yml`

```yaml
version: '3.8'

networks:
  public_net:
    driver: bridge
  app_net:
    driver: bridge

volumes:
  uploads-data:

services:
  gateway:
    build: ./gateway
    container_name: lauv-nginx-gateway
    ports:
      - "8080:80"
    depends_on:
      - frontend-service
      - backend-service
    networks:
      - public_net
      - app_net

  frontend-service:
    build: ./frontend
    container_name: lauv-frontend
    expose:
      - "80"
    networks:
      - app_net

  backend-service:
    build:
      context: .
      dockerfile: dockerfile
    container_name: lauv-backend
    expose:
      - "5000"
    environment:
      - NODE_ENV=production
      - PORT=5000
      - MONGO_URI=${MONGO_URI}
      - PAYPAL_CLIENT_ID=${PAYPAL_CLIENT_ID}
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - uploads-data:/var/data/uploads
    networks:
      - app_net
```

#### Environment Variables Setup
Create `.env` file in root:

```env
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname
PAYPAL_CLIENT_ID=your_paypal_client_id
JWT_SECRET=your_jwt_secret_key
```

#### Validation Checklist
- Start all services: `docker-compose up --build`
- Access frontend: `http://localhost:8080`
- Test API routes: `http://localhost:8080/api/health`
- Verify authentication flow (login/signup)
- Test file uploads to `/uploads/`
- Check order creation and payment flow
- Review logs: `docker-compose logs -f backend-service`

<img src="./screenshots/image.png">
Symlink works upload of files on containers successful 
<img src="./screenshots/symlink.png">
---

## Phase 6: Security Baseline & Trivy Image Scanning

### Goal
Implement automated vulnerability scanning to prevent deploying images with known security issues.

### Why This Matters
- Security should be built into the pipeline, not added as an afterthought
- Trivy detects CVEs in base images and dependencies
- Many enterprises fail builds automatically for HIGH/CRITICAL vulnerabilities
- Prevents known exploits from reaching production

### Tasks

#### Local Trivy Scan (Initial Testing)
```bash
# Build backend image
docker build -t lauv-backend:local -f dockerfile .

# Scan for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image lauv-backend:local

# Build and scan frontend
docker build -t lauv-frontend:local -f frontend/dockerfile ./frontend
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image lauv-frontend:local

# Build and scan gateway
docker build -t lauv-gateway:local -f gateway/dockerfile ./gateway
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image lauv-gateway:local
```

#### GitHub Actions Integration
Add to `.github/workflows/deploy.yml`

```yaml
- name: Scan backend image with Trivy
  uses: aquasecurity/trivy-action@v0.24.0
  with:
    image-ref: ${{ env.BACKEND_IMAGE }}
    severity: CRITICAL,HIGH
    ignore-unfixed: true
    exit-code: 1

- name: Scan frontend image with Trivy
  uses: aquasecurity/trivy-action@v0.24.0
  with:
    image-ref: ${{ env.FRONTEND_IMAGE }}
    severity: CRITICAL,HIGH
    ignore-unfixed: true
    exit-code: 1

- name: Scan gateway image with Trivy
  uses: aquasecurity/trivy-action@v0.24.0
  with:
    image-ref: ${{ env.GATEWAY_IMAGE }}
    severity: CRITICAL,HIGH
    ignore-unfixed: true
    exit-code: 1
```

#### Expected Outcome
- Pipeline fails if critical vulnerabilities detected
- Regular base image updates to patch CVEs
- Security reports in GitHub Actions logs

---

## Phase 7: AWS Networking (VPC, Subnets, Security Groups, NAT Gateway)

### Goal
Build isolated, production-grade network infrastructure for ECS and Application Load Balancer.

### Why This Matters
- ECS tasks should never be directly exposed to the internet
- Only ALB accepts public traffic; all services live in private subnets
- Controlled outbound access via NAT Gateway for ECR pulls and external APIs
- Network segmentation improves security posture

### Tasks

#### VPC Configuration
- Create VPC: `10.0.0.0/16` (65,536 IP addresses)
- Name: `lauv-prod-vpc`
- Enable DNS hostnames and DNS resolution

#### Public Subnets (for ALB and NAT Gateway)
- Public Subnet 1: `10.0.1.0/24` (Availability Zone us-east-1a)
- Public Subnet 2: `10.0.2.0/24` (Availability Zone us-east-1b)
- Attach Internet Gateway
- Route table: `0.0.0.0/0` → Internet Gateway

#### Private Subnets (for ECS Tasks)
- Private Subnet 1: `10.0.11.0/24` (Availability Zone us-east-1a)
- Private Subnet 2: `10.0.12.0/24` (Availability Zone us-east-1b)
- Route table: `0.0.0.0/0` → NAT Gateway

#### NAT Gateway
- Deploy NAT Gateway in Public Subnet 1
- Allocate Elastic IP
- Purpose: allow private subnet resources to access internet for updates and external APIs

#### Security Groups

**sg-alb (Application Load Balancer)**
```
Inbound Rules:
- Type: HTTPS, Port: 443, Source: 0.0.0.0/0 (IPv4)
- Type: HTTPS, Port: 443, Source: ::/0 (IPv6)
- Type: HTTP, Port: 80, Source: 0.0.0.0/0 (for redirect)

Outbound Rules:
- Type: HTTP, Port: 80, Destination: sg-ecs-app
```

**sg-ecs-app (ECS Tasks)**
```
Inbound Rules:
- Type: HTTP, Port: 80, Source: sg-alb
- Type: Custom TCP, Port: 5000, Source: sg-alb

Outbound Rules:
- Type: HTTPS, Port: 443, Destination: 0.0.0.0/0 (for ECR, MongoDB Atlas, APIs)
```

#### Architecture Flow
```
Internet → IGW → ALB (public subnets) → ECS Tasks (private subnets) → NAT Gateway → Internet (outbound only)
```

---

## Phase 8: ECR Repository Setup & Initial Image Push

### Goal
Establish centralized Docker registry for all container images.

### Why This Matters
- ECS pulls images directly from ECR within AWS private network
- Fast, secure image distribution
- Version control and image lifecycle policies
- Simplifies rollbacks and blue/green deployments

### Tasks

#### Create ECR Repositories
```bash
aws ecr create-repository --repository-name lauv-frontend --region us-east-1
aws ecr create-repository --repository-name lauv-backend --region us-east-1
aws ecr create-repository --repository-name lauv-nginx-gateway --region us-east-1
```

#### Configure Repository Policies
- Scan on push: enabled
- Tag immutability: recommended for production
- Lifecycle policies: retain last 10 images, delete untagged after 7 days

```bash
# Enable scan on push
aws ecr put-image-scanning-configuration \
  --repository-name lauv-backend \
  --image-scanning-configuration scanOnPush=true

# Set lifecycle policy
aws ecr put-lifecycle-policy \
  --repository-name lauv-backend \
  --lifecycle-policy-text '{
    "rules": [{
      "rulePriority": 1,
      "description": "Keep last 10 images",
      "selection": {
        "tagStatus": "any",
        "countType": "imageCountMoreThan",
        "countNumber": 10
      },
      "action": { "type": "expire" }
    }]
  }'
```

#### Authenticate Docker to ECR
```bash
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com
```

#### Tag and Push Images
```bash
# Backend
docker build -t lauv-backend:v1 -f dockerfile .
docker tag lauv-backend:v1 \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-backend:v1
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-backend:v1

# Frontend
docker build -t lauv-frontend:v1 -f frontend/dockerfile ./frontend
docker tag lauv-frontend:v1 \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-frontend:v1
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-frontend:v1

# Gateway
docker build -t lauv-nginx-gateway:v1 -f gateway/dockerfile ./gateway
docker tag lauv-nginx-gateway:v1 \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-nginx-gateway:v1
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-nginx-gateway:v1
```

---

## Phase 9: ECS Fargate Cluster & Task Definitions

### Goal
Deploy containers as managed, serverless tasks in private subnets using AWS Fargate.

### Why Fargate
- No EC2 instance management required
- Pay only for resources tasks consume
- Automatic scaling and high availability
- Simplified operations and maintenance

### Tasks

#### Create ECS Cluster
```bash
aws ecs create-cluster --cluster-name lauv-prod-cluster --region us-east-1
```

#### Task Execution Role
Create IAM role `ecsTaskExecutionRole` with policies:
- `AmazonECSTaskExecutionRolePolicy` (ECR pull, CloudWatch logs)
- Custom policy for SSM Parameter Store access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      "Resource": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:us-east-1:<account-id>:key/*"
    }
  ]
}
```

#### Task Role
Additional permissions for application runtime:
- S3 access (if needed for uploads)
- SES for emails
- Any other AWS service integrations

#### Backend Task Definition
Create file: `infra/backend-task-definition.json`

```json
{
  "family": "lauv-backend-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "backend",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-backend:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "PORT", "value": "5000"}
      ],
      "secrets": [
        {
          "name": "MONGO_URI",
          "valueFrom": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/MONGO_URI"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/JWT_SECRET"
        },
        {
          "name": "PAYPAL_CLIENT_ID",
          "valueFrom": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/PAYPAL_CLIENT_ID"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/lauv-backend",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

Register task definition:
```bash
aws ecs register-task-definition \
  --cli-input-json file://infra/backend-task-definition.json
```

#### Frontend Task Definition
Create file: `infra/frontend-task-definition.json`

```json
{
  "family": "lauv-frontend-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "frontend",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-frontend:latest",
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/lauv-frontend",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Gateway Task Definition
Create file: `infra/gateway-task-definition.json`

```json
{
  "family": "lauv-gateway-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "gateway",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/lauv-nginx-gateway:latest",
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/lauv-gateway",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Create CloudWatch Log Groups
```bash
aws logs create-log-group --log-group-name /ecs/lauv-backend
aws logs create-log-group --log-group-name /ecs/lauv-frontend
aws logs create-log-group --log-group-name /ecs/lauv-gateway
```

#### Create ECS Services
```bash
# Backend service
aws ecs create-service \
  --cluster lauv-prod-cluster \
  --service-name lauv-backend-service \
  --task-definition lauv-backend-task \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[subnet-xxx,subnet-yyy],
    securityGroups=[sg-ecs-app],
    assignPublicIp=DISABLED
  }"

# Frontend service
aws ecs create-service \
  --cluster lauv-prod-cluster \
  --service-name lauv-frontend-service \
  --task-definition lauv-frontend-task \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[subnet-xxx,subnet-yyy],
    securityGroups=[sg-ecs-app],
    assignPublicIp=DISABLED
  }"

# Gateway service (will be registered with ALB target group)
aws ecs create-service \
  --cluster lauv-prod-cluster \
  --service-name lauv-gateway-service \
  --task-definition lauv-gateway-task \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[subnet-xxx,subnet-yyy],
    securityGroups=[sg-ecs-app],
    assignPublicIp=DISABLED
  }" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=gateway,containerPort=80"
```

---

## Phase 10: Application Load Balancer, Route 53 & TLS (ACM)

### Goal
Expose application securely via HTTPS with custom domain `https://app.lauv.in`.

### Why This Matters
- Central SSL/TLS termination managed by AWS
- Path-based routing enables future microservices
- HTTPS required for modern web applications (PWA, secure cookies)
- Route 53 provides reliable DNS with health checks

### Tasks

#### Request ACM Certificate
```bash
aws acm request-certificate \
  --domain-name app.lauv.in \
  --validation-method DNS \
  --region us-east-1
```

Steps:
1. Copy DNS validation records from ACM console
2. Add CNAME records to Route 53 hosted zone for lauv.in
3. Wait for certificate status to become "Issued"

#### Create Application Load Balancer

**Create ALB**
```bash
aws elbv2 create-load-balancer \
  --name lauv-prod-alb \
  --subnets subnet-public1 subnet-public2 \
  --security-groups sg-alb \
  --scheme internet-facing \
  --type application \
  --ip-address-type ipv4
```

#### Target Groups

**Gateway Target Group**
```bash
aws elbv2 create-target-group \
  --name tg-lauv-gateway \
  --protocol HTTP \
  --port 80 \
  --vpc-id vpc-xxx \
  --target-type ip \
  --health-check-enabled \
  --health-check-path / \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3
```

#### ALB Listener Configuration

**HTTPS Listener (Port 443)**
```bash
aws elbv2 create-listener \
  --load-balancer-arn <alb-arn> \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=<acm-cert-arn> \
  --default-actions Type=forward,TargetGroupArn=<tg-gateway-arn>
```

**HTTP Listener (Port 80) - Redirect to HTTPS**
```bash
aws elbv2 create-listener \
  --load-balancer-arn <alb-arn> \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=redirect,RedirectConfig="{
    Protocol=HTTPS,
    Port=443,
    StatusCode=HTTP_301
  }"
```

#### Update Gateway ECS Service with Load Balancer
```bash
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-gateway-service \
  --load-balancers "targetGroupArn=<tg-gateway-arn>,containerName=gateway,containerPort=80"
```

#### Route 53 Configuration
```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id <zone-id> \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "app.lauv.in",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "<alb-hosted-zone-id>",
          "DNSName": "<alb-dns-name>",
          "EvaluateTargetHealth": true
        }
      }
    }]
  }'
```

#### Traffic Flow
```
User → HTTPS (443) → Route 53 (app.lauv.in) → ALB → Target Group → Gateway Service → Frontend/Backend Services
```

---

## Phase 11: Secrets Management via SSM Parameter Store

### Goal
Eliminate hardcoded secrets from images, code, and version control.

### Why This Matters
- Central, encrypted storage for sensitive configuration
- Secrets rotatable without redeploying code
- Audit trail for secret access
- Follows AWS security best practices

### Tasks

#### Store Parameters in SSM
```bash
aws ssm put-parameter \
  --name "/lauv/prod/MONGO_URI" \
  --value "mongodb+srv://username:password@cluster.mongodb.net/lauv" \
  --type SecureString \
  --key-id alias/aws/ssm

aws ssm put-parameter \
  --name "/lauv/prod/JWT_SECRET" \
  --value "your-secure-jwt-secret-min-32-chars" \
  --type SecureString \
  --key-id alias/aws/ssm

aws ssm put-parameter \
  --name "/lauv/prod/PAYPAL_CLIENT_ID" \
  --value "your-paypal-client-id" \
  --type SecureString \
  --key-id alias/aws/ssm

aws ssm put-parameter \
  --name "/lauv/prod/PAYPAL_CLIENT_SECRET" \
  --value "your-paypal-client-secret" \
  --type SecureString \
  --key-id alias/aws/ssm
```

#### Update Task Execution Role Policy
Already covered in Phase 9. Ensure the policy includes:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      "Resource": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:us-east-1:<account-id>:key/*"
    }
  ]
}
```

#### Reference in Task Definition
Already implemented in backend task definition (Phase 9):

```json
"secrets": [
  {
    "name": "MONGO_URI",
    "valueFrom": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/MONGO_URI"
  },
  {
    "name": "JWT_SECRET",
    "valueFrom": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/JWT_SECRET"
  },
  {
    "name": "PAYPAL_CLIENT_ID",
    "valueFrom": "arn:aws:ssm:us-east-1:<account-id>:parameter/lauv/prod/PAYPAL_CLIENT_ID"
  }
]
```

#### Verification
- Secrets injected at container runtime
- Not visible in task definition JSON
- Not baked into Docker images
- Can rotate by updating SSM parameter and restarting tasks

---

## Phase 12: CI/CD Pipeline with GitHub Actions

### Goal
Automate build, security scan, push, and deployment on every commit to main branch.

### Why This Matters
- Consistent, repeatable deployment process
- No manual steps reduces human error
- Trivy scanning enforces security gates
- Fast feedback loop for developers

### Tasks

#### Create Workflow File
Located at `.github/workflows/deploy.yml`

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

env:
  AWS_REGION: us-east-1
  ECR_REGISTRY: <account-id>.dkr.ecr.us-east-1.amazonaws.com
  BACKEND_IMAGE: lauv-backend
  FRONTEND_IMAGE: lauv-frontend
  GATEWAY_IMAGE: lauv-nginx-gateway

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1

      - name: Build backend image
        run: |
          docker build -t ${{ env.ECR_REGISTRY }}/${{ env.BACKEND_IMAGE }}:${{ github.sha }} \
            -f dockerfile .
          docker tag ${{ env.ECR_REGISTRY }}/${{ env.BACKEND_IMAGE }}:${{ github.sha }} \
            ${{ env.ECR_REGISTRY }}/${{ env.BACKEND_IMAGE }}:latest

      - name: Scan backend image with Trivy
        uses: aquasecurity/trivy-action@v0.24.0
        with:
          image-ref: ${{ env.ECR_REGISTRY }}/${{ env.BACKEND_IMAGE }}:${{ github.sha }}
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: 1

      - name: Push backend image
        run: |
          docker push ${{ env.ECR_REGISTRY }}/${{ env.BACKEND_IMAGE }}:${{ github.sha }}
          docker push ${{ env.ECR_REGISTRY }}/${{ env.BACKEND_IMAGE }}:latest

      - name: Build frontend image
        run: |
          docker build -t ${{ env.ECR_REGISTRY }}/${{ env.FRONTEND_IMAGE }}:${{ github.sha }} \
            -f frontend/dockerfile ./frontend
          docker tag ${{ env.ECR_REGISTRY }}/${{ env.FRONTEND_IMAGE }}:${{ github.sha }} \
            ${{ env.ECR_REGISTRY }}/${{ env.FRONTEND_IMAGE }}:latest

      - name: Scan frontend image with Trivy
        uses: aquasecurity/trivy-action@v0.24.0
        with:
          image-ref: ${{ env.ECR_REGISTRY }}/${{ env.FRONTEND_IMAGE }}:${{ github.sha }}
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: 1

      - name: Push frontend image
        run: |
          docker push ${{ env.ECR_REGISTRY }}/${{ env.FRONTEND_IMAGE }}:${{ github.sha }}
          docker push ${{ env.ECR_REGISTRY }}/${{ env.FRONTEND_IMAGE }}:latest

      - name: Build gateway image
        run: |
          docker build -t ${{ env.ECR_REGISTRY }}/${{ env.GATEWAY_IMAGE }}:${{ github.sha }} \
            -f gateway/dockerfile ./gateway
          docker tag ${{ env.ECR_REGISTRY }}/${{ env.GATEWAY_IMAGE }}:${{ github.sha }} \
            ${{ env.ECR_REGISTRY }}/${{ env.GATEWAY_IMAGE }}:latest

      - name: Scan gateway image with Trivy
        uses: aquasecurity/trivy-action@v0.24.0
        with:
          image-ref: ${{ env.ECR_REGISTRY }}/${{ env.GATEWAY_IMAGE }}:${{ github.sha }}
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: 1

      - name: Push gateway image
        run: |
          docker push ${{ env.ECR_REGISTRY }}/${{ env.GATEWAY_IMAGE }}:${{ github.sha }}
          docker push ${{ env.ECR_REGISTRY }}/${{ env.GATEWAY_IMAGE }}:latest

      - name: Update ECS services
        run: |
          aws ecs update-service --cluster lauv-prod-cluster \
            --service lauv-backend-service --force-new-deployment
          
          aws ecs update-service --cluster lauv-prod-cluster \
            --service lauv-frontend-service --force-new-deployment
          
          aws ecs update-service --cluster lauv-prod-cluster \
            --service lauv-gateway-service --force-new-deployment

      - name: Wait for services to stabilize
        run: |
          aws ecs wait services-stable --cluster lauv-prod-cluster \
            --services lauv-backend-service lauv-frontend-service lauv-gateway-service
```

#### GitHub Secrets Configuration
Add to repository secrets (Settings → Secrets and variables → Actions):
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

Create IAM user with policies:
- `AmazonEC2ContainerRegistryPowerUser`
- `AmazonECS_FullAccess`

#### Pipeline Flow
```
Commit to main → Build Images → Trivy Scan → Push to ECR → Force ECS Deployment → Rolling Update
```

#### Rollback Strategy
To rollback to previous version:
```bash
# Find previous task definition revision
aws ecs describe-task-definition --task-definition lauv-backend-task

# Update service to use previous revision
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-backend-service \
  --task-definition lauv-backend-task:PREVIOUS_REVISION
```

---

## Phase 13: CloudWatch Logs & Metrics

### Goal
Implement minimum viable observability: centralized logs and key performance metrics.

### Why This Matters
- Debug production issues without SSH access
- Track application health and performance trends
- Foundation for alerting and autoscaling decisions
- Required for production readiness

### Tasks

#### Configure CloudWatch Log Groups
Already configured in task definitions (Phase 9). Set retention policies:

```bash
aws logs put-retention-policy \
  --log-group-name /ecs/lauv-backend \
  --retention-in-days 30

aws logs put-retention-policy \
  --log-group-name /ecs/lauv-frontend \
  --retention-in-days 30

aws logs put-retention-policy \
  --log-group-name /ecs/lauv-gateway \
  --retention-in-days 30
```

#### Create CloudWatch Alarms

**High 5xx Error Rate**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name lauv-alb-high-5xx \
  --alarm-description "Alert on high 5xx errors from ALB" \
  --metric-name HTTPCode_Target_5XX_Count \
  --namespace AWS/ApplicationELB \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=LoadBalancer,Value=app/lauv-prod-alb/xxx
```

**High CPU Utilization - Backend**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name lauv-backend-high-cpu \
  --alarm-description "Alert on sustained high CPU" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 3 \
  --threshold 70 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=ClusterName,Value=lauv-prod-cluster Name=ServiceName,Value=lauv-backend-service
```

**High Memory Utilization - Backend**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name lauv-backend-high-memory \
  --alarm-description "Alert on sustained high memory usage" \
  --metric-name MemoryUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 3 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=ClusterName,Value=lauv-prod-cluster Name=ServiceName,Value=lauv-backend-service
```

**Target Response Time**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name lauv-alb-slow-response \
  --alarm-description "Alert on slow target response times" \
  --metric-name TargetResponseTime \
  --namespace AWS/ApplicationELB \
  --statistic Average \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 2.0 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=LoadBalancer,Value=app/lauv-prod-alb/xxx
```

#### SNS Topic for Alerts
```bash
# Create SNS topic
aws sns create-topic --name lauv-prod-alerts

# Subscribe email
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:<account-id>:lauv-prod-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# Update alarms to send to SNS
aws cloudwatch put-metric-alarm \
  --alarm-name lauv-alb-high-5xx \
  --alarm-actions arn:aws:sns:us-east-1:<account-id>:lauv-prod-alerts
```

#### Key Metrics to Monitor
- ALB request count and latency
- Target response time
- HTTP 4xx and 5xx error counts
- ECS CPU and memory utilization
- Task health status
- Active connection count

#### CloudWatch Insights Queries

**Backend Error Logs**
```
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 100
```

**API Response Times**
```
fields @timestamp, @message
| parse @message /method=(?<method>\w+) path=(?<path>[^\s]+) status=(?<status>\d+) duration=(?<duration>\d+)/
| stats avg(duration), max(duration), p95(duration) by path
```

---

## Phase 14: Prometheus & Grafana (Observability)

### Goal
Implement application-level metrics collection and visualization for deep insights.

### Why This Matters
- CloudWatch provides infrastructure metrics, Prometheus provides application metrics
- Grafana dashboards are more developer-friendly and customizable
- Industry standard for modern observability
- Real-time monitoring of business metrics

### Tasks

#### Deploy Monitoring Stack

**Option 1: Fargate Task (Recommended)**

Create `infra/monitoring-task-definition.json`:

```json
{
  "family": "lauv-monitoring-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "prometheus",
      "image": "prom/prometheus:latest",
      "portMappings": [
        {
          "containerPort": 9090,
          "protocol": "tcp"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "prometheus-config",
          "containerPath": "/etc/prometheus"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/lauv-monitoring",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "prometheus"
        }
      }
    },
    {
      "name": "grafana",
      "image": "grafana/grafana:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "GF_SECURITY_ADMIN_PASSWORD", "value": "changeme"},
        {"name": "GF_SERVER_ROOT_URL", "value": "http://monitoring.lauv.in"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/lauv-monitoring",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "grafana"
        }
      }
    }
  ],
  "volumes": [
    {
      "name": "prometheus-config",
      "host": {}
    }
  ]
}
```

**Option 2: EC2 Instance**
- Launch t3.small in private subnet
- Install Docker and Docker Compose
- Run Prometheus + Grafana containers

#### Prometheus Configuration
Create `infra/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'nginx-gateway'
    static_configs:
      - targets: ['gateway-service.local:9113']
    
  - job_name: 'backend-app'
    static_configs:
      - targets: ['backend-service.local:9090']
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['backend-service.local:9100']
```

#### Instrument Backend Application
Install Prometheus client:

```bash
npm install prom-client
```

Add to `backend/server.js`:

```javascript
const promClient = require('prom-client');

// Create a Registry
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// Create custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const httpRequestTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

// Middleware to track metrics
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route ? req.route.path : req.path;
    
    httpRequestDuration
      .labels(req.method, route, res.statusCode)
      .observe(duration);
    
    httpRequestTotal
      .labels(req.method, route, res.statusCode)
      .inc();
  });
  
  next();
});

// Expose metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

#### Nginx Metrics Exporter
Update `gateway/dockerfile`:

```dockerfile
FROM nginx:alpine

# Install nginx-prometheus-exporter
RUN apk add --no-cache wget && \
    wget https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v0.11.0/nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz && \
    tar xzf nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz && \
    mv nginx-prometheus-exporter /usr/local/bin/ && \
    rm nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 9113

# Start nginx and exporter
CMD nginx && nginx-prometheus-exporter -nginx.scrape-uri=http://localhost:80/stub_status
```

Update `gateway/nginx.conf` to enable stub_status:

```nginx
server {
    listen 80;
    server_name _;

    location /stub_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }

    # ... rest of config
}
```

#### Grafana Dashboards

**Import Pre-built Dashboards**
1. Nginx metrics dashboard: ID 12708
2. Node.js application metrics: ID 11159
3. ECS container metrics: ID 551

**Create Custom Dashboard**

Panels to include:
- Request rate by endpoint (graph)
- Response time percentiles p50, p95, p99 (graph)
- Error rate by status code (graph)
- Active user sessions (stat)
- Database query duration (heatmap)
- HTTP request distribution (bar chart)

Sample Prometheus queries:

```promql
# Request rate
rate(http_requests_total[5m])

# Response time p95
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Error rate
rate(http_requests_total{status_code=~"5.."}[5m])
```

#### Access Grafana Securely

**Option 1: Internal ALB**
- Create internal ALB in private subnets
- Connect via VPN or bastion host

**Option 2: AWS Systems Manager Port Forwarding**
```bash
aws ssm start-session \
  --target <ecs-task-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3000"],"localPortNumber":["3000"]}'
```

Access at `http://localhost:3000`

---

## Phase 15: Reliability, Scaling & Operational Runbooks

### Goal
Transform deployment into a reliable, scalable production system with documented operational procedures.

### Why This Matters
- Autoscaling handles traffic spikes automatically
- Health checks prevent routing to unhealthy tasks
- Runbooks reduce mean-time-to-recovery during incidents
- Cost optimization prevents budget overruns

### Tasks

#### ECS Service Autoscaling

**Target Tracking Policy (CPU-based)**
```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/lauv-prod-cluster/lauv-backend-service \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 2 \
  --max-capacity 10

# Create scaling policy
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/lauv-prod-cluster/lauv-backend-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name cpu-target-tracking \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleInCooldown": 300,
    "ScaleOutCooldown": 60
  }'
```

**Request Count Based Scaling**
```bash
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/lauv-prod-cluster/lauv-gateway-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name request-count-scaling \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 1000.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ALBRequestCountPerTarget",
      "ResourceLabel": "app/lauv-prod-alb/xxx/targetgroup/tg-lauv-gateway/yyy"
    }
  }'
```

#### Health Checks

**Backend Health Check Endpoint**
Add to `backend/server.js`:

```javascript
app.get('/api/health', async (req, res) => {
  try {
    // Check MongoDB connection
    await mongoose.connection.db.admin().ping();
    
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      mongodb: 'connected'
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});
```

**Update Target Group Health Check**
```bash
aws elbv2 modify-target-group \
  --target-group-arn <tg-gateway-arn> \
  --health-check-path /api/health \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3
```

#### Operational Runbooks

**Runbook 1: Rollback Deployment**

When to use: New deployment causing errors or performance issues

Steps:
```bash
# 1. Find previous working task definition revision
aws ecs describe-task-definition --task-definition lauv-backend-task

# 2. Update service to previous revision
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-backend-service \
  --task-definition lauv-backend-task:PREVIOUS_REVISION

# 3. Monitor rollback
aws ecs describe-services \
  --cluster lauv-prod-cluster \
  --services lauv-backend-service

# 4. Verify health
curl https://app.lauv.in/api/health
```

**Runbook 2: Restart Service**

When to use: Service frozen, memory leaks, unresponsive

Steps:
```bash
# Force new deployment (graceful restart)
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-backend-service \
  --force-new-deployment

# OR stop all tasks (ECS will start new ones)
aws ecs list-tasks --cluster lauv-prod-cluster \
  --service-name lauv-backend-service \
  --query 'taskArns[]' --output text | \
  xargs -n1 aws ecs stop-task --cluster lauv-prod-cluster --task
```

**Runbook 3: Scale Service Manually**

When to use: Expected traffic spike, emergency scaling

Steps:
```bash
# Scale up to 10 tasks
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-backend-service \
  --desired-count 10

# Scale down to 2 tasks
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-backend-service \
  --desired-count 2
```

**Runbook 4: Rotate Secrets**

When to use: Security breach, regular rotation policy

Steps:
```bash
# 1. Update secret in SSM
aws ssm put-parameter \
  --name "/lauv/prod/JWT_SECRET" \
  --value "new-secure-secret" \
  --type SecureString \
  --overwrite

# 2. Force service restart to pick up new secret
aws ecs update-service \
  --cluster lauv-prod-cluster \
  --service lauv-backend-service \
  --force-new-deployment

# 3. Verify new secret is loaded
aws ecs execute-command \
  --cluster lauv-prod-cluster \
  --task <task-id> \
  --container backend \
  --command "/bin/sh" \
  --interactive
# Then: echo $JWT_SECRET
```

**Runbook 5: Debug Failed Deployment**

When to use: Deployment stuck, tasks failing to start

Steps:
```bash
# 1. Check service events
aws ecs describe-services \
  --cluster lauv-prod-cluster \
  --services lauv-backend-service \
  --query 'services[0].events[0:10]'

# 2. Check task stopped reason
aws ecs describe-tasks \
  --cluster lauv-prod-cluster \
  --tasks <task-id> \
  --query 'tasks[0].stoppedReason'

# 3. Check CloudWatch logs
aws logs tail /ecs/lauv-backend --follow

# 4. Common issues:
#    - Image pull errors: Check ECR permissions
#    - Health check failures: Check /api/health endpoint
#    - Resource constraints: Increase CPU/memory in task def
#    - Secret access errors: Check task execution role
```

#### Cost Optimization

**Current Monthly Cost Estimate**
- ALB: $16-20
- NAT Gateway: $32-45 (with data transfer)
- Fargate tasks (2x256/512): $15-20
- ECR storage: $1-2
- CloudWatch logs: $5-10
- MongoDB Atlas: $57 (M10 tier)
- Route 53: $0.50
- ACM: Free

**Total: ~$125-155/month**

**Optimization Strategies**
1. Use single NAT Gateway instead of one per AZ (reduce $32/month)
2. Implement CloudWatch log filtering to reduce ingestion
3. Use ECR lifecycle policies to delete old images
4. Consider Reserved Capacity for Fargate if traffic is predictable
5. Use AWS Compute Savings Plans for 20-30% discount
6. Monitor idle resources with AWS Cost Explorer

**Cost Monitoring**
```bash
# Create budget alert
aws budgets create-budget \
  --account-id <account-id> \
  --budget '{
    "BudgetName": "lauv-monthly-budget",
    "BudgetLimit": {
      "Amount": "200",
      "Unit": "USD"
    },
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }' \
  --notifications-with-subscribers '[{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80
    },
    "Subscribers": [{
      "SubscriptionType": "EMAIL",
      "Address": "your-email@example.com"
    }]
  }]'
```

#### Disaster Recovery

**Backup Strategy**
- MongoDB Atlas: automatic daily backups (enabled by default)
- ECS task definitions: stored in S3 or version control
- Docker images: stored in ECR with lifecycle policies
- Infrastructure as Code: stored in Git repository

**Recovery Time Objective (RTO)**
- Service restart: 2-3 minutes
- Rollback deployment: 5-10 minutes
- Full infrastructure rebuild: 30-60 minutes

**Recovery Point Objective (RPO)**
- Database: 1 hour (Atlas continuous backup)
- Application state: near-zero (stateless services)

---

## Summary & Next Steps

### What We've Built
A production-grade, scalable e-commerce platform with:
- Multi-tier architecture (gateway, frontend, backend)
- Automated CI/CD pipeline
- Security scanning and secrets management
- Comprehensive monitoring and alerting
- Auto-scaling and high availability
- Operational runbooks for incident response

### Deployment Checklist
- [ ] Phase 1: Repository structure and branching
- [ ] Phase 2: Backend Dockerization
- [ ] Phase 3: Frontend Dockerization
- [ ] Phase 4: Gateway Dockerization
- [ ] Phase 5: Local Docker Compose testing
- [ ] Phase 6: Trivy security scanning
- [ ] Phase 7: AWS networking (VPC, subnets, security groups)
- [ ] Phase 8: ECR repositories and image push
- [ ] Phase 9: ECS Fargate cluster and task definitions
- [ ] Phase 10: ALB, Route 53, and ACM certificate
- [ ] Phase 11: SSM Parameter Store secrets
- [ ] Phase 12: GitHub Actions CI/CD pipeline
- [ ] Phase 13: CloudWatch logs and alarms
- [ ] Phase 14: Prometheus and Grafana
- [ ] Phase 15: Autoscaling and runbooks

### Future Enhancements
1. Blue/Green deployments for zero-downtime releases
2. AWS WAF for application-layer DDoS protection
3. ElastiCache (Redis) for session management and caching
4. S3 + CloudFront for static asset delivery
5. AWS Backup for automated disaster recovery
6. Infrastructure as Code (Terraform or CloudFormation)
7. Multi-region deployment for global availability
8. Chaos engineering with AWS Fault Injection Simulator
9. Cost optimization with Spot instances for non-critical workloads
10. Advanced security with AWS GuardDuty and Security Hub

### Support and Maintenance
- Monitor CloudWatch alarms daily
- Review CloudWatch Insights weekly for error patterns
- Update Docker base images monthly for security patches
- Rotate secrets quarterly
- Review and optimize costs monthly
- Test disaster recovery procedures quarterly
- Update runbooks after each incident

---

<div align="center">

**⭐ If this guide helped you, please star the repository! ⭐**

Made with ❤️ for the DevOps community

</div>