FROM node:20-alpine

WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1

COPY package*.json ./
COPY . .

RUN npm ci
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]
