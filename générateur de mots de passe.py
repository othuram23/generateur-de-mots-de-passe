# -*- coding: utf-8 -*-
"""
Created on Mon Jul 29 20:04:24 2024

@author: Thuram OTCHOUN
"""
import string
import random
import time
import os
import bcrypt
import requests
import base64
import binascii
import urllib.parse
import hashlib
import hmac
import codecs
import pickle

compteur = 0
# Historique des mots de passe générés
password_history = []


def fetch_common_patterns(common_patterns_path):
    """
    Reads a text file from the local machine containing common passwords.

    Parameters:
    common_patterns_path (str): Path to the local text file.

    Returns:
    list: List of common passwords or patterns.
    """
    common_patterns_frgit = []

    try:
        with open(common_patterns_path, 'r', encoding='utf-8') as file:
            common_patterns_frgit = file.read().splitlines()
            time.sleep(1)
    except FileNotFoundError:
        print(f"Fichier non trouvé: {common_patterns_path}")

    my_common_patterns = ["qwe", "asd", "zxc", "admin", "letmein", "welcome", "monkey",
                          "iloveyou", "sunshine", "princess", "dragon", "football", "baseball", "superman", "batman",
                          "trustno1", "1234", "abcd", "qwerty", "asdf", "zxcv", "pass", "love", "god", "secret",
                          "master", "hello", "freedom", "whatever", "shadow", "killer", "ninja", "michael", "jessica",
                          "charlie", "bubbles", "tigger", "cookie", "pepper", "ginger", "summer", "winter", "spring",
                          "autumn", "flower", "xyz", "rainbow", "butterfly", "password", '123456', '123456789', "guest",
                          "qwerty",
                          '12345678', '111111', '12345', 'col123456', '123123', '1234567', '1234', '1234567890',
                          '000000',
                          '555555', '666666', '123321', '654321', '7777777', '123', 'password', 'abc', 'qwerty']
    common_patterns = common_patterns_frgit + my_common_patterns

    return common_patterns


def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    """
    Génère un mot de passe aléatoire basé sur les critères spécifiés.

    Parameters:
    length (int): Longueur du mot de passe. Valeur par défaut est 12.
    use_upper (bool): Inclure des lettres majuscules. Valeur par défaut est True.
    use_lower (bool): Inclure des lettres minuscules. Valeur par défaut est True.
    use_digits (bool): Inclure des chiffres. Valeur par défaut est True.
    use_special (bool): Inclure des caractères spéciaux. Valeur par défaut est True.

    Returns:
    str: Le mot de passe généré.

    Raises:
    ValueError: Si aucun type de caractère n'est sélectionné.
    """
    if not (use_upper or use_lower or use_digits or use_special):
        raise ValueError("Au moins un type de caractère doit être sélectionné")

    char_pool = (
            (string.ascii_uppercase if use_upper else '') +
            (string.ascii_lowercase if use_lower else '') +
            (string.digits if use_digits else '') +
            (string.punctuation if use_special else '')
    )
    time.sleep(1)
    password = ''.join(random.choice(char_pool) for _ in range(length))
    return password


def hash_password(password):
    """
    Hachage d'un mot de passe avec bcrypt.

    Parameters:
    password (str): Le mot de passe en clair.

    Returns:
    str: Le mot de passe haché.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def count_lines_in_file(filepath):
    """
    Compte le nombre de lignes dans un fichier.

    Parameters:
    filepath (str): Le chemin complet du fichier.

    Returns:
    int: Le nombre de lignes dans le fichier.
    """
    count = 0
    with open(filepath, 'r') as f:
        for _ in f:
            count += 1

    return count


def change_directory():
    """
    Demande à l'utilisateur s'il veut changer de répertoire et le déplace si nécessaire.

    Returns:
    str: Le nouveau répertoire ou l'ancien répertoire s'il n'y a pas de changement.
    """
    change_dir = input("Voulez-vous changer de répertoire pour l'enregistrement? (oui/non): ").strip().lower()

    if change_dir == 'oui':
        while True:
            directory = input("Entrez le nouveau répertoire: ").strip()
            time.sleep(1)
            if os.path.isdir(directory):
                os.chdir(directory)
                return os.getcwd()
            else:
                print("Le répertoire spécifié n'existe pas. Réessayez.")
    else:
        default_dir = 'C:/Users/Admin/'
        return default_dir


def create_or_append_file(directory, filename, password):
    """
    Vérifie si un fichier existe dans un répertoire spécifié.
    S'il existe, ajoute un bloc de code sans retourner d'exception.
    S'il n'existe pas, le crée et écrit 'Bonjour' sur une nouvelle ligne.

    Parameters:
    directory (str): Le répertoire où chercher/créer le fichier.
    filename (str): Le nom du fichier à chercher/créer.
    password (str): Le mot de passe à écrire dans le fichier.
    """
    filepath = os.path.join(directory, filename)

    if os.path.exists(filepath):
        print(f"Le fichier {filepath} existe. Enrégistrement du mot de passe...")

        with open(filepath, 'a') as f:
            time.sleep(1)
            f.write(f"Mot de passe No {count_lines_in_file(filepath=filepath) + 1} : {password} \n")
    else:
        print(f"Le fichier {filepath} n'existe pas. Création et écriture du fichier.")

        with open(filepath, 'w') as f:
            time.sleep(1)
            f.write(f"Mot de passe No {count_lines_in_file(filepath=filepath) + 1} : {password}\n")


def save_password_to_file(password, directory, filename):
    """
    Sauvegarde le mot de passe dans un fichier sous forme hachée.

    Parameters:
    password (str): Le mot de passe à sauvegarder.
    filename (str): Le nom du fichier où sauvegarder le mot de passe.
    directory (str): Le répertoire où sauvegarder le fichier.
    """
    hashed_password = hash_password(password)  # Hachage du mot de passe

    create_or_append_file(directory, filename, hashed_password)  # Passez le mot de passe haché à la fonction


def evaluate_password_strength(password, common_patterns):
    """
    Évalue la force du mot de passe.

    Parameters:
    password (str): Le mot de passe à évaluer.

    Returns:
    str: La force du mot de passe ('Très faible', 'Faible', 'Moyenne', 'Bonne', 'Très bonne').
    """
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    unique_chars = len(set(password))
    time.sleep(1)

    # Vérifier la présence de motifs communs dans le mot de passe à évaluer
    has_common_pattern = any(pattern in password for pattern in common_patterns)

    # Calcul du score
    score = 0
    score += 1 if length >= 8 else 0
    score += 1 if length >= 12 else 0
    score += 1 if length >= 16 else 0
    score += 1 if has_upper else 0
    score += 1 if has_lower else 0
    score += 1 if has_digit else 0
    score += 1 if has_special else 0
    score += 1 if unique_chars >= 6 else 0
    score -= 1 if has_common_pattern else 0

    # Déterminer la force du mot de passe
    if score <= 2:
        strength = 'Très faible'
    elif score <= 4:
        strength = 'Faible'
    elif score <= 6:
        strength = 'Moyen'
    elif score <= 8:
        strength = 'Bon'
    else:
        strength = 'Très bon'

    return strength


def main():
    """
    Fonction principale pour exécuter le programme de gestion des mots de passe.

    """
    print("\n\nBienvenue dans Keychain, le générateur et gestionnaire de mots de passe créé avec le language de programmation python.")
    print("\nQue voulez-vous faire ?")
    liste_de_choix = [
        "Générer un mot de passe",
        "Consulter l'historique de création des mots de passe",
        "Encoder une chaîne de caractères",
        "Décoder une chaîne de caractères",
        "Évaluer la force d'un mot de passe",
        "Hasher une chaîne de caractères",
        "Quitter le programme"
    ]
    for choix in liste_de_choix:
        print(f"{liste_de_choix.index(choix) + 1} - {choix}")

    select = int(input("\nSélectionnez l'option qui vous convient: "))

    if select == 1:
        begin_with_personal_values = input(
            "\nVoulez-vous utiliser les valeurs par défaut ? (oui/non): ").strip().lower() == 'non'

        if begin_with_personal_values:
            length = int(input("Spécifiez la longueur du mot de passe que vous souhaitez générer: "))
            use_upper = input(
                "Voulez-vous que le mot de passe comporte des lettres majuscules ? (oui/non): ").strip().lower() == 'oui'
            use_lower = input(
                "Voulez-vous que le mot de passe comporte des lettres minuscules ? (oui/non): ").strip().lower() == 'oui'
            use_digits = input(
                "Voulez-vous que le mot de passe comporte des nombres ? (oui/non): ").strip().lower() == 'oui'
            use_special = input(
                "Voulez-vous que le mot de passe comporte des caractères spéciaux ? (oui/non): ").strip().lower() == 'oui'

            password = generate_password(length=length, use_upper=use_upper, use_lower=use_lower, use_digits=use_digits,
                                         use_special=use_special)

        else:
            password = generate_password()

        if len(password_history) > 50:
            password_history.pop(0)  # Enlever le premier élément de l'historique

        print(f'\nMot de passe généré: {password}')
        print("\nCryptage et sauvegarde des mots de passe sur la machine....")
        time.sleep(1)
        password_history.append(password)

        directory = change_directory()  # Correction de l'appel de change_directory
        if directory != 'C:/Users/Admin/':

            filename = input("\nEntrez le nom du fichier où sauvegarder le mot de passe: ").strip()
            save_password_to_file(password=password, directory=directory, filename=filename)
            time.sleep(1)
            print("\nMot de passe sauvegardé avec succès!")

        else:
            save_password_to_file(password=password, directory='C:/Users/Admin/', filename='passwords.txt')
            time.sleep(1)
            print("\nMot de passe sauvegardé avec succès!")

    elif select == 2:
        if not password_history:
            print("\nAucun mot de passe n'a été généré pour le moment.")
        else:
            print("\nVoici l'historique des mots de passe que nous avons générés pour vous: ")
            time.sleep(1)
            for i, pwd in enumerate(password_history, 1):
                print(f'{i} - {pwd}')

    elif select == 3:

        data = str(input("\nEntrez la chaîne de caractères à encoder: "))

        print("\nChoisissez le type d'encodage que vous voulez utiliser: ")

        liste_encodages = ["Base64", "Hexadécimal", "UTF-8", "ASCII", "Codage URL", "Base32", "Base16", "ROT13"]

        for i, encodable in enumerate(liste_encodages, 1):
            print(f"{i} - {encodable}")

        select_encodage = int(input("\nFaites votre choix: ").strip())

        if select_encodage == 1:

            encoded_data_base_64 = base64.b64encode(data.encode('utf-8'))
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_base_64.decode('utf-8'))

        elif select_encodage == 2:

            encoded_data_hex = binascii.hexlify(data.encode('utf-8'))
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_hex.decode('utf-8'))

        elif select_encodage == 3:

            encoded_data_utf8 = data.encode('utf-8')
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_utf8.decode('utf-8'))

        elif select_encodage == 4:

            encoded_data_ascii = data.encode('ascii')
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_ascii.decode('ascii'))

        elif select_encodage == 5:

            encoded_data_urlparse = urllib.parse.quote(data)
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_urlparse)

        elif select_encodage == 6:

            encoded_data_base_32 = base64.b32encode(data.encode('utf-8'))
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_base_32.decode('utf-8'))

        elif select_encodage == 7:

            encoded_data_base_16 = base64.b16encode(data.encode('utf-8'))
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_base_16.decode('utf-8'))

        elif select_encodage == 8:

            encoded_data_rot_13 = codecs.encode(data, 'rot_13')
            time.sleep(1)
            print("\nRésultat de l'encodage:", encoded_data_rot_13)

        else:

            print("\nOption d'encodage non reconnue. Veuillez réessayer.")

    elif select == 4:

        data = str(input("\nEntrez la chaîne de caractères à décoder: "))
        print("\nChoisissez le type de décodage que vous voulez utiliser: ")
        liste_decodages = ["Base64", "Hexadécimal", "UTF-8", "ASCII", "Codage URL", "Base32", "Base16", "ROT13"]

        for i, decodable in enumerate(liste_decodages, 1):
            print(f"{i} - {decodable}")

        select_decodage = int(input("\nFaites votre choix: ").strip())

        if select_decodage == 1:

            try:

                decoded_data_base_64 = base64.b64decode(data).decode('utf-8')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_base_64)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage Base64:", e)

        elif select_decodage == 2:

            try:

                decoded_data_hex = binascii.unhexlify(data).decode('utf-8')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_hex)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage Hexadécimal:", e)

        elif select_decodage == 3:

            try:

                decoded_data_utf8 = data.encode('utf-8').decode('utf-8')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_utf8)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage UTF-8:", e)

        elif select_decodage == 4:

            try:

                decoded_data_ascii = data.encode('ascii').decode('ascii')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_ascii)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage ASCII:", e)

        elif select_decodage == 5:

            try:

                decoded_data_urlparse = urllib.parse.unquote(data)
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_urlparse)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage Codage URL:", e)

        elif select_decodage == 6:

            try:

                decoded_data_base_32 = base64.b32decode(data).decode('utf-8')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_base_32)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage Base32:", e)

        elif select_decodage == 7:

            try:

                decoded_data_base_16 = base64.b16decode(data).decode('utf-8')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_base_16)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage Base16:", e)

        elif select_decodage == 8:

            try:
                decoded_data_rot_13 = codecs.decode(data, 'rot_13')
                time.sleep(1)
                print("\nRésultat du décodage:", decoded_data_rot_13)

            except Exception as e:
                time.sleep(1)
                print("\nErreur lors du décodage ROT13:", e)

        else:
            time.sleep(1)
            print("\nOption de décodage non reconnue. Veuillez réessayer.")

    elif select == 5:

        password = input("\nEntrez le mot de passe à évaluer: ").strip()
        common_patterns_path = input(
            "\nEntrer le nouveau répertoire du fichier common_patterns.txt (après dézippage de l'archive): ").strip()
        common_patterns = fetch_common_patterns(common_patterns_path)
        strength = evaluate_password_strength(password, common_patterns)
        time.sleep(1)
        print(f"\nForce du mot de passe: {strength}")

    elif select == 6:
        print("\nAu revoir!")
        exit()
    else:
        print("\nOption non reconnue. Veuillez réessayer.")


if __name__ == "__main__":
    main()
    compteur += 1

    if compteur == 1:
        time.sleep(1)
        compteur = 0

if compteur == 0:
    main()
