FROM node:lts-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps
COPY index.html vite.config.js tailwind.config.js postcss.config.js ./
COPY src/ src/
COPY public/ public/
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY conf/dashboard.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
