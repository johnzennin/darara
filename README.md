# SQLMap GUI

PyQt5 ile geliştirilmiş grafiksel SQLMap arayüzü.

## Özellikler

- **Hedef Yapılandırması**: URL, POST verisi, cookie, user-agent ayarları
- **İstek Ayarları**: Proxy, Tor, gecikme, zaman aşımı yapılandırması
- **Optimizasyon**: Thread sayısı, keep-alive, null connection seçenekleri
- **Enjeksiyon**: Risk seviyesi, test parametreleri, injection tipi seçimi
- **Tespit**: String matching, regex, HTTP kod filtreleme
- **Teknikler**: Boolean-based, error-based, union, stacked, time-based injection seçenekleri
- **Numaralandırma**: Veritabanı, tablo, sütun, kullanıcı, yetki sorgulama
- **Filtreleme**: Regex filtreleri, sistem tablolarını hariç tutma
- **Genel Ayarlar**: Verbose seviyesi, batch mod, WAF tespiti, oturum yönetimi

## Gereksinimler

- Python 3.6+
- PyQt5
- SQLMap (sistemde kurulu olmalı)

## Kurulum

```bash
# PyQt5 kurulumu
pip install PyQt5

# SQLMap kurulumu (eğer yoksa)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

## Kullanım

```bash
python sqlmap_gui.py
```

veya

```bash
./sqlmap_gui.py
```

## Kullanım Talimatları

1. **SQLMap Yolunu Ayarla**: Eğer SQLMap otomatik bulunamazsa, Ayarlar menüsünden SQLMap yolunu belirtin.

2. **Hedef Belirle**: "Hedef" sekmesinden hedef URL'yi girin veya istek dosyası yükleyin.

3. **Ayarları Yapılandır**: İhtiyacınıza göre diğer sekmelerdeki ayarları yapın.

4. **Komutu Önizle**: Alt kısımda oluşturulan SQLMap komutunu görebilirsiniz.

5. **Çalıştır**: "Çalıştır" butonuna basarak işlemi başlatın.

6. **Çıktıyı İzle**: Gerçek zamanlı olarak çıktıyı izleyebilir, kaydedebilir veya temizleyebilirsiniz.

## Önemli Not

⚠️ **Bu araç sadece eğitim ve yasal güvenlik testleri için kullanılmalıdır.**

İzinsiz sistemlere karşı SQL enjeksiyon testi yapmak yasa dışıdır ve suç teşkil eder. 
Yalnızca kendi sisteminizde veya yazılı izin aldığınız sistemlerde kullanın.

## Ekran Görüntüsü

Uygulama koyu tema ile tasarlanmıştır ve şu bölümleri içerir:
- Üst kısım: Yapılandırma sekmeleri ve komut önizleme
- Alt kısım: Gerçek zamanlı çıktı terminali

## Lisans

GPLv2

## Katkıda Bulunma

Geliştirmeler için pull request gönderebilirsiniz.

## Bağlantılar

- [SQLMap Resmi Sitesi](https://sqlmap.org)
- [SQLMap GitHub](https://github.com/sqlmapproject/sqlmap)
- [PyQt5 Dokümantasyonu](https://www.riverbankcomputing.com/static/Docs/PyQt5/)
