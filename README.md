[![Docker CI/CD](https://github.com/trydirect/status/actions/workflows/ci.yml/badge.svg)](https://github.com/trydirect/status/actions/workflows/ci.yml)
![Docker Stars](https://img.shields.io/docker/stars/trydirect/status.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/trydirect/status.svg)
![Docker Automated](https://img.shields.io/docker/cloud/automated/trydirect/status.svg)
![Docker Build](https://img.shields.io/docker/cloud/build/trydirect/status.svg)
[![Gitter chat](https://badges.gitter.im/trydirect/community.png)](https://gitter.im/try-direct/community)
<br><br><br><br>
<div align="center">
<img width="300" src="https://raw.githubusercontent.com/trydirect/status/testing/assets/logo/status.png"> 
 </div>
 <div align="center">
A minimal docker container management panel written in Python / Flask
</div>
<br><br><br><br>


<center><img width="1063" alt="Screen Shot 2019-05-21 at 12 45 11 PM" src="https://raw.githubusercontent.com/trydirect/status/testing/assets/screenshot.png"></center>

## Under the hood
 * Python 3.9
 * Flask latest
 

## Note
Before installing this project, please, make sure you have installed docker and docker-compose

To install docker execute: 
```sh
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ sh get-docker.sh
$ pip install docker-compose
```

## Installation
Clone this project into your work directory:
```sh
$ git clone "https://github.com/trydirect/status.git"
```

## How to start:
```sh
$ cd status
$ docker-compose up -d
```


## How to build:
```sh
$ cd status
$ docker-compose -f docker-compose-build.yml build
```


## Contributing

1. Fork it (<https://github.com/trydirect/status/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

## Feature request
https://github.com/trydirect/status/issues

## Support new features development

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2BH8ED2AUU2RL)
