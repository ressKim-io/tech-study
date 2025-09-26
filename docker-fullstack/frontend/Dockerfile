# 빌드 스테이지
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN npm install -g serve
COPY . .
RUN npm run build

# 프로덕션 스테이지
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
RUN npm install -g serve
COPY --from=builder /app/build ./build
EXPOSE 3000
CMD ["npm", "run", "serve"]
