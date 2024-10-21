FROM node:17-alpine
WORKDIR /frontend
COPY package.json .
RUN npm install
COPY . .
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait
EXPOSE 3000
CMD ./wait && npm start