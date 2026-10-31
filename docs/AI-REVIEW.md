# Review a website report with your AI assistant

Layerly SEO Basics is an optional instruction file for interpreting this checker's JSON output. It adds no executable code, hosted integration, model SDK or API key requirement to the crawler. Your assistant's subscription, file-reading and code-execution capabilities are separate.

## 1. Try it without contacting a website

From a reviewed checkout of this repository, with Python 3.11 to 3.13:

```bash
python -m sitecheck demo --out sample.json
python -m sitecheck validate sample.json
```

The first command creates a synthetic fixture report without network requests. The second validates its structure using the checker. Keep the sample label visible; the observations do not describe your own site.

Give your assistant these two files:

- [`skills/layerly-seo-basics/SKILL.md`](../skills/layerly-seo-basics/SKILL.md)
- The generated `sample.json` file, or the existing [`examples/sample-report.json`](../examples/sample-report.json).

If your assistant can read repository files, provide their paths. Otherwise, attach or paste their contents. Merely providing a GitHub URL does not prove that the assistant has opened the files or can execute code. You do not need to install the skill globally to try these instructions.

Use this prompt:

```text
Read skills/layerly-seo-basics/SKILL.md and the attached JSON report.
Explain the findings in plain language, using page URLs and evidence IDs.
Separate measured facts, contextual interpretation, and proposed fixes.
Explain missing coverage and say which findings need business context.
Do not invent issues or a ranking score. Keep synthetic data labelled.
Interpret the supplied files only; do not crawl, edit a site or send anything.
```

## 2. Check a site you are authorised to test

After reviewing the code and confirming the target and scope:

```bash
python -m sitecheck check https://your-authorized-domain.example/ --live --out report.json
python -m sitecheck validate report.json
```

Replace the example domain. This contacts the target website and DNS under the checker's limits. By default it selects up to five HTML pages, with at most twenty HTTP attempts including supporting requests. For a separately agreed larger scope, add `--max-pages 100`; this enables recursive same-host discovery with at most 400 HTTP attempts and a soft 600-second job timer. Use the actual limits and coverage in the report, not an assumed whole-site scope. Robots restrictions apply. It is not an entire-site audit.

Review the report for sensitive URLs, excerpts and diagnostic addresses before sharing it with an assistant or anyone else. The CLI does not automatically upload, encrypt or delete the file.

Give the assistant the skill and `report.json` using the prompt above. If it cannot execute code, run the CLI yourself and provide the output. Do not describe a check as performed when no execution evidence exists.

## 3. Turn observations into useful decisions

Ask the assistant to identify the page, observation, supporting evidence, possible consequence, proposed action and way to verify the fix. A short justified list is better than filling a quota of problems.

- A missing JSON-LD block is an observation, not automatically a defect.
- A page with noindex or a non-self canonical may be intentionally configured.
- HTTP 200 and a self canonical do not prove Google indexation.
- `partial` can reflect an intentionally untested external link even when all five pages were fetched. Read the coverage reasons before recommending more work.
- Rankings, traffic, backlinks, AI citations, JavaScript rendering and conversions are outside this checker.

The assistant interprets evidence; its wording is not an independent measurement. Confirm recommendations against page intent and relevant documentation before making changes. Editing, deployment, outreach and account connections require their own authorised scope.

## فارسی: متن آماده برای شروع

ابتدا فایل مهارت و گزارش JSON را ضمیمه کنید و این متن را بدهید:

```text
فایل skills/layerly-seo-basics/SKILL.md و گزارش JSON پیوست را بخوان.
به فارسی توضیح بده چه چیزهایی اندازه‌گیری شده، چه چیزهایی بررسی نشده و
کدام مشاهده واقعاً نیازمند اصلاح یا اطلاعات بیشتر است.
برای هر یافته، صفحه و شاهد معتبر گزارش را مشخص کن.
واقعیت، برداشت و پیشنهاد را جدا نگه دار. ایراد، رتبه یا نتیجه تجاری نساز.
اگر داده ساختگی است، برچسب آن را حفظ کن.
فقط همین فایل‌ها را تفسیر کن؛ خزش، تغییر سایت یا ارسال انجام نده.
```

## Get help or contribute

The standalone checker and skill are free under this repository's [MIT license](../LICENSE). You can adapt the interpretation workflow without sending your report to Layerly. Human interpretation and implementation are optional: [request a focused review](https://layerly.net/website-check/#request).

For improvements to the skill, follow [CONTRIBUTING.md](../CONTRIBUTING.md). Use public or synthetic reports with permission, preserve sample labels, and exclude customer data and credentials.
