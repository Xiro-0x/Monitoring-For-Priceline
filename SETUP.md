🐛 Priceline H1 Recon — Setup Guide
⚠️ اقرا هادشي قبل — Rules ديال البرنامج
من الـ policy الرسمية ديال Priceline (HackerOne):
X-Bug-Bounty header واجب — أي active request بلا header = الـ WAF كيبلوكيك.
السكريبت كيصيفط X-Bug-Bounty: xiro0x_1 تلقائياً فـ httpx/ffuf/katana/nuclei ✅
ممنوع DoS / spam — الـ rates محدودين (httpx 150/s, ffuf 150/s, nuclei 30/s) ✅
ممنوع تصيفط scanner reports — النتائج ديال هاد الـ recon هي نقطة بداية غير ليك نتا،
verify بيدك قبل ما تصيفط أي report
Rate-limiting issues + version disclosure + missing headers = Out of scope (Informative)
*.priceline.com فيه scope ولكن الـ bounty على حسب impact
ملي تصيفط report: ذكر الـ header + الـ IP ديالك + استعمل H1 email alias للحسابات
🎯 الـ scope المغطى بالأوتوماتيك
Feuilles de calcul
Asset	مغطى؟
priceline.com (+ wildcard: www, cruises, press, ... )	✅ subdomain enum
getaroom.com	✅
flyiin.com	✅
bookingholdings.com (ir., www.)	✅
bookingholdings-coe.com	✅
Penny AI (/penny)	❌ manual (prompt injection/business logic)
Android/iOS apps	❌ manual (mobile testing)
/pwd/v0/pcln-graphql/	⚡ جزئياً — كيظهر فـ katana/params crawling ديال www.priceline.com
🚀 التركيب (5 دقائق)
1. دير repo جديد: Monitoring-Recon-Priceline
⚠️ ما تحطش هاد الـ workflow فنفس الـ repo ديال FSR — بجوج كيكتبو last_subs.txt
وغادي يتخربق الـ diff. Repo مستقل = نظيف.
2. الملفات (فالجذر ROOT — ماشي .github/!)
plain
Monitoring-Recon-Priceline/
├── recon.sh          ← من هاد الـ zip
├── notify.py         ← من هاد الـ zip
└── .github/
    └── workflows/
        └── recon.yml ← من هاد الـ zip
3. Secrets
Feuilles de calcul
Secret	واجب؟	القيمة
DISCORD_WEBHOOK_URL	✅	نفس الـ webhook ولا channel جديد (مستحسن: channel خاص بـ Priceline)
H1_USERNAME	اختياري	default: xiro0x_1 — بدلو إلا بدلتي الـ username ديالك فـ H1
TARGETS	اختياري	default: الـ 5 domains. بدلو إلا تبدل الـ scope
CENSYS_API_KEY CHAOS_API_KEY SHODAN_API_KEY VIRUSTOTAL_API_KEY	اختياري	نفس keys ديال FSR — كيزيدو subdomains بزاف
4. Run workflow يدوياً
علامة النجاح: رسالة "🚀 Priceline H1 Recon started" فـ Discord من بعد ~2min.
📊 شنو تتوقع
المدة: ~40-90 min (5 domains + tools من cache من المرة التانية)
Subdomains: Priceline عندهم infrastructure كبيرة — تتوقع مئات/آلاف
Discord: embed + FINAL_REPORT.txt + @everyone غير على subdomains جداد
Artifacts: priceline-recon-N.zip فيه كلشي (params, JS, gf patterns, nuclei...)
🔁 كيفاش تخدم بالنتائج
04_classified/internal.txt → staging/dev/admin panels = أحسن أهداف
06_files/gf/ → params مصنفين (xss/sqli/ssrf) — verify يدوياً بـ PoC
06_files/interesting_dirs.txt → .git/.env/swagger...
07_fingerprint/nuclei_exposures.txt → exposures (verify قبل report!)
أي subdomain جديد كيوصلك alert — جرب subdomain takeover (مقبول حتى على out-of-scope assets عندهم)
⚡ إلا بغيتي تبدل الـ targets
بلا secrets: بدل السطر فـ recon.yml:
yaml
TARGETS: ${{ secrets.TARGETS || 'domain1.com,domain2.com' }}
ولا زيد secret سميتو TARGETS بالليستة الجديدة (بلا ما تبدل الكود).
السكريبت كيخدم مع domain بوحد، ليستة بفواصل، ولا فايل.
