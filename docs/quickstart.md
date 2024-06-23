# Quickstart
You need a clean Ubuntu Linux version 24 (Noble Numbat) with 4CPU, 8GB RAM and 40GB DISK.
All commands are executed as root.  

## 1. Build Kubntu setup package
```bash
cd ~
apt install -y git
git clone https://github.com/bihalu/kubntu.git
cd kubntu
./kubntu-build-1.29.4.sh
```
Takes about 10 minutes ...  
coffe break ;-)

## 2. Setup kubernetes single node cluster 
```bash
./kubntu-setup-1.29.4.tgz.self init single
```
Takes about 5 minutes ...  
almost done   

## 3. Inspect your kubernetes cluster with k9s
You can have a look at the cluster with k9s tool.  

```bash
k9s
```

![k9s screenshot](k9s.png)
Pods are running.  

## Summary
You can set up a kubernetes cluster in under half an hour. If you have already built the setup and app package it is even faster. Save these packages on a usb stick and you can quickly set up a kubernetes cluster in no time.  

``/\_/\``  
``(='_')``   
``(,(")(")`` 
