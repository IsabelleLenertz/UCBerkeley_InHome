# UCBerkeley_InHome
UC Berkeley MICS capstone project: Zero Trust Architecture to protect home network

# Installation steps
This project has been created to run on a Debian base Lunix distribution. It will not work on Mac and windows devices. There no guarantee it will work on other distributions.
Install libpicap:
    sudo apt-get install libpcap-dev
Install JbcConnector for C++:
    Download the version that matches your ubuntu from here: https://dev.mysql.com/downloads/connector/cpp/8.0.html
    sudo apt-get install libmysqlcppconn-dev_8.0.32-1ubuntu22.04_amd64.deb
Install Docker and Docker-compose:

Build the routing engine:
    cd routing_engine
    make
Go to the build directory and start the newly created program

# Starting the router
go to the root folder:
    docker-compose up
    docker-compose down (those two commands are needed the first time to make sure the database starts before the java-based API)
    docker-compose up
Go to the rouing_engine/build directory and start the routing engine

# Setting up device configurations
With your browser, natigate to <add front-end address here>.
Default password is <insert password here>, you'll be prompted to create a new password
Add device configurations and policies authorizing communications using the administrator interface
