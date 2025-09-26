FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN adduser -D appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 5000
CMD ["npm", "start"]
