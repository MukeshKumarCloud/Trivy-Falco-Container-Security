# Intentionally vulnerable — DO NOT USE IN PRODUCTION
FROM nginx:1.21.0

# Hardcoded secrets — realistic patterns that trigger secret scanners
ENV DB_PASSWORD="P@ssw0rd!Mysql#2024"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

COPY index.html /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
