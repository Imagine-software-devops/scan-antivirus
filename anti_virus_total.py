import os
import zipfile
import requests

# Voir la biblio de virustotal
# re demander une cley d'api


# Fonction pour lire la clé d'API à partir du fichier api_key.txt
def get_api_key():
    with open('api_key.txt', 'r') as f:
        return f.read().strip()

# URL de l'API de VirusTotal pour analyser un fichier
SCAN_URL = 'https://www.virustotal.com/api/v3/files'

# Classe VirusTotalScanner pour gérer les fonctionnalités de l'API VirusTotal
class VirusTotalScanner:
    def __init__(self):
        self.api_key = get_api_key()  # Récupère la clé d'API à partir du fichier api_key.txt

    def get_file_report(self, file_hash):
        headers = {
            'x-apikey': self.api_key,
        }
        params = {
            'fields': 'data.attributes.last_analysis_results',
        }
        # Envoie une requête GET à l'API de VirusTotal pour obtenir le rapport d'analyse du fichier
        response = requests.get(f'{SCAN_URL}/{file_hash}', headers=headers, params=params)
        if response.status_code == 200:
            return response.json()  # Renvoie le rapport au format JSON s'il est disponible
        else:
            return None

    def upload_and_scan_zip(self, zip_file_path):
        with open(zip_file_path, 'rb') as f:
            files = {'file': (zip_file_path, f)}
            headers = {
                'x-apikey': self.api_key,
            }
            # Envoie une requête POST à l'API de VirusTotal pour analyser le fichier zip
            response = requests.post(SCAN_URL, headers=headers, files=files)
            if response.status_code == 200:
                data = response.json()
                file_hash = data['data']['id']  # Récupère l'ID de fichier à partir de la réponse de l'API
                return self.get_file_report(file_hash)  # Récupère le rapport d'analyse du fichier
            else:
                return None

# Fonction pour créer un fichier zip à partir d'un dossier spécifié
def zip_folder(folder_path, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, relative_path)

# Fonction principale
def main():
    # Remplacez 'folder_to_zip' par le chemin du dossier que vous souhaitez zipper
    folder_to_zip = 'chemin/vers/votre/dossier'
    # Remplacez 'output_zip_file.zip' par le chemin du fichier zip de sortie
    output_zip_file = 'output_zip_file.zip'

    # Création du fichier zip
    zip_folder(folder_to_zip, output_zip_file)
    
    # Création de l'objet VirusTotalScanner
    scanner = VirusTotalScanner()

    # Envoi du fichier zip à VirusTotal pour analyse
    result = scanner.upload_and_scan_zip(output_zip_file)
    if result:
        print(result)
    else:
        print('La requête a échoué ou le rapport n\'a pas été trouvé.')

if __name__ == '__main__':
    main()
