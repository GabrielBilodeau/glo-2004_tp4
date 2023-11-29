"""\
GLO-2000 Travail pratique 4 - Client
Noms et numéros étudiants:
-
-
-
"""

import argparse
import getpass
import json
import socket
import sys

import glosocket
import gloutils


class Client:
    """Client pour le serveur mail @glo2000.ca."""

    def __init__(self, destination: str) -> None:
        """
        Prépare et connecte le socket du client `_socket`.

        Prépare un attribut `_username` pour stocker le nom d'utilisateur
        courant. Laissé vide quand l'utilisateur n'est pas connecté.
        """

        self._username = None

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._socket.connect((destination, gloutils.APP_PORT))
        except socket.error:
            sys.exit(1)

    def _register(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_REGISTER`.

        Si la création du compte s'est effectuée avec succès, l'attribut
        `_username` est mis à jour, sinon l'erreur est affichée.
        """
        register_username = input("Entrez votre nom d'utilisateur: ")
        register_password = getpass.getpass("Entrez votre mot de passe: ")

        register_payload = gloutils.AuthPayload(
            username=register_username,
            password=register_password
        )

        message = json.dumps(gloutils.GloMessage(
            header=gloutils.Headers.AUTH_REGISTER,
            payload=register_payload
        ))
        glosocket.send_mesg(self._socket, message)

        reponse = glosocket.recv_mesg(self._socket)
        json_reponse = json.loads(reponse)

        if json_reponse['header'] == gloutils.Headers.OK:
            self._username = register_username
        elif json_reponse['header'] == gloutils.Headers.ERROR:
            print(json_reponse['payload']["error_message"])
        else:
            print("Invalid server response")


    def _login(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_LOGIN`.

        Si la connexion est effectuée avec succès, l'attribut `_username`
        est mis à jour, sinon l'erreur est affichée.
        """

        login_username = input("Entrez votre nom d'utilisateur: ")
        login_password = getpass.getpass("Entrez votre mot de passe: ")

        credentials = gloutils.AuthPayload(
            username=login_username,
            password=login_password
        )

        message = json.dumps(
            gloutils.GloMessage(
                header=gloutils.Headers.AUTH_LOGIN,
                payload=credentials
            )
        )

        glosocket.send_mesg(self._socket, message)

        response = glosocket.recv_mesg(self._socket)
        json_response = json.loads(response)
        if json_response["header"] == gloutils.Headers.OK:
            self._username = login_username
        elif json_response["header"] == gloutils.Headers.ERROR:
            print(json_response["payload"]["error_message"])
        else:
            print("Invalid server response")
    

    def _quit(self) -> None:
        """
        Préviens le serveur de la déconnexion avec l'entête `BYE` et ferme le
        socket du client.
        """
        message = json.dumps(gloutils.GloMessage(
                            header=gloutils.Headers.BYE
                        ))
        glosocket.send_mesg(self._socket, json.dumps(message))
        self._socket.close()

    def _read_email(self) -> None:
        """
        Demande au serveur la liste de ses courriels avec l'entête
        `INBOX_READING_REQUEST`.

        Affiche la liste des courriels puis transmet le choix de l'utilisateur
        avec l'entête `INBOX_READING_CHOICE`.

        Affiche le courriel à l'aide du gabarit `EMAIL_DISPLAY`.

        S'il n'y a pas de courriel à lire, l'utilisateur est averti avant de
        retourner au menu principal.
        """

        request = gloutils.GloMessage(
            header=gloutils.Headers.INBOX_READING_REQUEST
        )
        glosocket.send_mesg(self._socket, json.dumps(request))

        response = json.loads(glosocket.recv_mesg(self._socket))
        if response["header"] == gloutils.Headers.OK:
            email_list = response["payload"]["email_list"]
            if len(email_list) > 0:
                for email in email_list:
                    print(email)

                mail_choice = input(f"Entrez votre choix [1-{len(email_list)}]")

                choice_payload = gloutils.EmailChoicePayload(
                    choice = int(mail_choice)
                )

                choice_request = gloutils.GloMessage(
                    header=gloutils.Headers.INBOX_READING_CHOICE,
                    payload=choice_payload
                )

                glosocket.send_mesg(self._socket, json.dumps(choice_request))

                content_response = json.loads(glosocket.recv_mesg(self._socket))

                if content_response["header"] == gloutils.Headers.OK:
                    mail_content = content_response["payload"]
                    sender = mail_content["sender"]
                    destination = mail_content["destination"]
                    subject = mail_content["subject"]
                    date = mail_content["date"]
                    content = mail_content["content"]

                    print(gloutils.EMAIL_DISPLAY.format(
                        sender=sender,
                        to=destination,
                        subject=subject,
                        date=date,
                        body=content
                    ))
        elif response["header"] == gloutils.Headers.ERROR:
            print(response["payload"]["error_message"])
        else:
            print("Invalid server response")

    def _send_email(self) -> None:
        """
        Demande à l'utilisateur respectivement:
        - l'adresse email du destinataire,
        - le sujet du message,
        - le corps du message.

        La saisie du corps se termine par un point seul sur une ligne.

        Transmet ces informations avec l'entête `EMAIL_SENDING`.
        """

        sender = self._username
        destination = input("Entrez l'addresse du destinataire :")
        subject = input("Entrez le sujet: ")
        print("""Entrez le contenu du courriel,
              terminez la saisie avec un '.' seul sur une ligne: """)
        body = ""
        buffer = ""
        while (buffer != ".\n"):
            body += buffer
            buffer = input() + '\n'
        date = gloutils.get_current_utc_time()

        email = gloutils.EmailContentPayload(
            sender=sender + "@" + gloutils.SERVER_DOMAIN,
            destination=destination,
            subject=subject,
            date=date,
            content=body
        )

        message = gloutils.GloMessage(
            header=gloutils.Headers.EMAIL_SENDING,
            payload=email
        )

        glosocket.send_mesg(self._socket, json.dumps(message))

        response = json.loads(glosocket.recv_mesg(self._socket))
        if response["header"] == gloutils.Headers.OK:
            print("Email envoye avec succes")
        else:
            print(response["payload"]["error_message"])


    def _check_stats(self) -> None:
        """
        Demande les statistiques au serveur avec l'entête `STATS_REQUEST`.

        Affiche les statistiques à l'aide du gabarit `STATS_DISPLAY`.
        """

        request = gloutils.GloMessage(header=gloutils.Headers.STATS_REQUEST)

        glosocket.send_mesg(self._socket, json.dumps(request))

        response = json.loads(glosocket.recv_mesg(self._socket))

        if response["header"] == gloutils.Headers.OK:
            count = response["payload"]["count"]
            size = response["payload"]["size"]

            print(gloutils.STATS_DISPLAY.format(
                count=count,
                size=size
            ))

    def _logout(self) -> None:
        """
        Préviens le serveur avec l'entête `AUTH_LOGOUT`.

        Met à jour l'attribut `_username`.
        """

        logout_request = gloutils.GloMessage(header=gloutils.Headers.AUTH_LOGOUT)

        glosocket.send_mesg(self._socket, json.dumps(logout_request))

        response = json.loads(glosocket.recv_mesg(self._socket))

        if response["headers"] == gloutils.Headers.OK:
            self._username = None

    def run(self) -> None:
        """Point d'entrée du client."""
        should_quit = False

        while not should_quit:
            if not self._username:
                # Authentication menu
                print(gloutils.CLIENT_AUTH_CHOICE + "\n")
                choice = input("Entrez votre choix [1-3]: ")

                match choice:
                    case "1":
                        self._register()
                    case "2":
                        self._login()
                    case "3":
                        self._quit()
                        should_quit = True
                    case _:
                        continue
            else:
                # Main menu
                print(gloutils.CLIENT_USE_CHOICE + "\n")
                choice = input("Entrez votre choix [1-4]: ")

                match choice:
                    case "1":
                        self._read_email()
                    case "2":
                        self._send_email()
                    case "3":
                        self._check_stats()
                    case 4:
                        self._logout()

    def _validate_domain(p_destination: str) -> bool:
        good_domain = False
        
        #Check if the end of the string is the right domain name
        if p_destination[-11:] == f"@{gloutils.SERVER_DOMAIN}":
            good_domain = True
        
        return good_domain


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--destination", action="store",
                        dest="dest", required=True,
                        help="Adresse IP/URL du serveur.")
    args = parser.parse_args(sys.argv[1:])
    client = Client(args.dest)
    client.run()
    return 0


if __name__ == '__main__':
    sys.exit(_main())
