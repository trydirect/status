## Use an official Node runtime as a parent image
#FROM node:16-alpine
#
## Set the working directory in the container
#WORKDIR /usr/src/app
#
## Copy package.json and package-lock.json
#COPY package*.json ./
#
## Install dependencies
#RUN npm install --only=production
#
## Copy project files
#COPY . .
#
## Expose the application port
#EXPOSE 3456
#
## Set environment variables if needed
#ENV NODE_ENV production
#
## Build the application
#RUN npm run build
#
## Command to run the application
#CMD ["npm", "run", "serve"]

FROM node:16-alpine as builder
WORKDIR /app
COPY . .
RUN npm install --only=production
RUN npm run build

# Stage 2: Final production image
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
EXPOSE 3456
CMD ["npm", "run", "serve"]