"""Human-readable publication receipt; never modifies measured artifacts or URIs.

Called after verify-public, before commit. The workflow uses publication_at for
both Git dates. STATUS.md is visible on checked only when that commit is pushed;
it is not a second measurement or a claim about the exact network push time.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def write_status(output, publication_at):
    root = Path(output)
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', publication_at):
        raise ValueError('publication timestamp must be UTC seconds')
    at = datetime.fromisoformat(publication_at.replace('Z', '+00:00'))
    report = json.loads((root / 'report.json').read_bytes())
    started = datetime.fromisoformat(report['started_at'])
    completed = datetime.fromisoformat(report['completed_at'])
    if not started <= completed <= at:
        raise ValueError('publication precedes measurement')
    production = report['production']
    run_id = production['run_id']
    if not re.fullmatch(r'[0-9]{1,20}', run_id):
        raise ValueError('invalid run id')
    counts = {}
    for key, filename in [('main', 'subscription-youtube-stable.txt'),
                          ('reserve', 'subscription-youtube-reserve.txt')]:
        counts[key] = len((root / filename).read_text().splitlines())
    text = f'''# Последняя опубликованная проверка

- Время commit публикации (UTC): **{publication_at}**
- Начало замороженного снимка источников (UTC): {report['started_at']}
- Проверки и сборка отчёта завершены (UTC): {report['completed_at']}
- Основной список: **{counts['main']}**; резерв: **{counts['reserve']}**
- [Запуск GitHub Actions](https://github.com/zruzus1-prog/vpn-checked/actions/runs/{run_id})
- [Подробный отчёт](report.json)

Время commit не является временем проверки каждого сервера или точным временем
приёма push GitHub. Эта страница попадает в ветку checked атомарно с подписками.
При неудаче следующего запуска дата здесь остаётся прежней. Через 12 часов
от начала снимка источников считайте его устаревшим; Karing может продолжать хранить его до обновления.
Расписание запрашивает запуск каждый час, но GitHub может задержать или пропустить
его. Проверки выполняются из облака, доступность из вашей сети не гарантирована.
'''
    (root / 'STATUS.md').write_text(text)
    return text


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--publication-at', required=True)
    args = parser.parse_args()
    write_status(args.output, args.publication_at)
