document.getElementById('checkButton').addEventListener('click', function() {
    const urlInput = document.getElementById('urlInput').value;
    const resultMessage = document.getElementById('resultMessage');
    const resultDiv = document.getElementById('result');

    // Kullanıcı URL girdi mi?
    if (urlInput.trim() === "") {
        resultMessage.textContent = "Lütfen bir URL girin.";
        resultDiv.className = "result error";
        resultDiv.style.display = "block";
        return;
    }

    // URL'yi VirusTotal ile kontrol et
    checkWithVirusTotal(urlInput, resultMessage, resultDiv);
});

function checkWithVirusTotal(url, resultMessage, resultDiv) {
    const apiKey = "VIRUS_TOTAL_API_KEY"; // VirusTotal API anahtarınızı buraya yerleştirin
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${btoa(url).replace(/=/g, '')}`;
    
    // Sonuçları al ve ekrana yaz
    fetch(apiUrl, {
        method: 'GET',
        headers: {
            'x-apikey': apiKey,
        }
    })
    .then(response => response.json())
    .then(data => {
        const malicious = data.data.attributes.last_analysis_stats.malicious;
        if (malicious > 0) {
            resultMessage.textContent = "URL Zararlı! Oltalama (Phishing) Tehditi Tespit Edildi.";
            resultDiv.className = "result invalid";
        } else {
            resultMessage.textContent = "Bu URL Zararlı Değil.";
            resultDiv.className = "result valid";
        }
        resultDiv.style.display = "block";
    })
    .catch(error => {
        resultMessage.textContent = "Bir hata oluştu. Lütfen tekrar deneyin.";
        resultDiv.className = "result error";
        resultDiv.style.display = "block";
        console.error(error);
    });
}
