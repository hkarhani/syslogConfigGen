# Syslog Config Generator
Starterkit of Syslog Parsing for Forescout.   

You need to run a docker Container with Jupyter Notebook - which will allow you to Generate and Edit and simulate your Syslog configurations.

## 1. Build & Run your Docker Container

1. Build your own Container:
`docker build -t sysloggen .`

2. Simply Run :
  `docker run --name syslogGen -d -p 8888:8888 sysloggen`

 Then browse to http://docker-machine-ip:8888/ (if local machine use: localhost:8888).

3. Open the Notebook: 1. syslog Model Generator Tutorial.ipynb - and execute the cells to Generate Syslog Configurations on Forescout Platform.

4. OPen the Notebook: 2. pySyslog Testing - To Simulate Syslog Messages to your Forescout Platform.

Video Tutorial is available upon request, and Notebooks are quiet easy to follow. 
