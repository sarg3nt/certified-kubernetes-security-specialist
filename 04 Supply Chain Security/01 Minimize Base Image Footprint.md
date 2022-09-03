# Minimize Base Image Footprint

 - Be aware of the base / parent image.  Use the smallest one with the least dependencies possible
 - Do not build images that include multiple components (web + database)
 - Do not store state inside the container.  Always store data in an external volume or caching layer like Redis
 - When looking for base images
   - Official
   - Upd to date
   - Slim / Minimal
   - Only install necessary packages.  
   - Remove tools like 
     - Shells
     - Package Managers (yum, apt-get)
     - curl
     - wget
 - Maintain different images for different environments
   - Development - debug tools
   - Production - lean
 - Use Multi-stage builds to create lead production ready images

Googles Distroless Docker Images

Contains:
- Application
- Runtime Dependencies
  
Does not contain:
- Package Managers
- Shells
- Network Tools
- Text Editors
- Other unwanted programs

https://github.com/GoogleContainerTools/distroless

Minimal images are far less vulnerable to attacks.  
- httpd debian 10.8 had 124 vulnerabilities
- httpd alpine 3.12.4 had 0

