# kalibro

### How to run:
- catcher:
    ```
    $ sudo python3 catcher.py --sniff --mysql

    multi device:
    $ sudo python3 catcher.py --sniff --mysql --port=12345

    ```
- scanner:
    ```
    $ sudo python3 scanner.py [device] [band]

    example:
    $ sudo python3 scanner.py bladerf0 GSM900

    ```
- grgsm livemon:
    ```
    $ sudo grgsm_livemon_headless -f [freq]

    example:
    $ sudo grgsm_livemon_headless -f 936.8M

    multi device:
    $ sudo grgsm_livemon_headless -f 936.8M --serverport=12345 --collectorport=12345
    ```
