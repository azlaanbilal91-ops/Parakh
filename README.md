# Parakh: website bharosa checker

Yeh ek chhota Node.js server hai (koi package install nahi karna). Node 18 ya naya chahiye.

## Kya kya check hota hai
- Domain kab register hua (RDAP)
- SSL certificate sahi hai ya nahi
- Google Safe Browsing aur URLhaus ki khatarnak list
- Link ki shakal (brand ki nakal, shak wale alfaaz, risky extension, IP address)

Agar API key nahi lagi to khatarnak list wala check band rehta hai aur score 70 se upar nahi jata.

## Keys hasil karna
1. **Google Safe Browsing** (zaroori): console.cloud.google.com par naya project banayen, "Safe Browsing API" enable karein, Credentials mein "API key" banayen. Yeh sirf ghair-tijarati istemal ke liye muft hai. Agar app se paisay kamane hain to Google Web Risk API chahiye (paid).
2. **URLhaus** (optional): auth.abuse.ch par muft account banayen aur Auth-Key lein.

## Apne computer par chalana
```
GOOGLE_SAFE_BROWSING_KEY=aapki_key node server.js
```
Phir browser mein http://localhost:3000 kholein.

## Internet par daalna (Render.com, muft plan)
1. Poora folder GitHub par naye repository mein upload karein.
2. render.com par "New > Web Service" chunein aur apna repository jorein.
3. Build Command khali chhor dein, Start Command: `node server.js`
4. Environment mein `GOOGLE_SAFE_BROWSING_KEY` (aur chahein to `URLHAUS_AUTH_KEY`) daalein.
5. Deploy ke baad aap ko https wala link mil jayega. Muft plan par pehli request mein 30 se 60 second lag sakte hain.

## Play Store ke liye
Website chalne ke baad us https link se PWABuilder.com (ya Bubblewrap) ke zariye Android app (TWA) banayi ja sakti hai. Play Console ke liye privacy policy page aur 12 testers ke saath 14 din ki testing (naye personal accounts ke liye) chahiye hoti hai.
