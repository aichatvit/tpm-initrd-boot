# Сборка и проверка на Windows + VMware Workstation Pro

Все Linux-команды ниже выполняются **в Ubuntu-госте**, не в PowerShell.
WSL для этого варианта не нужен. Проверка реального EFI-пути в VMware ещё
не выполнялась автором проекта; это воспроизводимая инструкция для её проведения.

## 1. Виртуальная машина

Создайте отдельную VM Ubuntu 24.04 LTS x86-64: 2 CPU, 4 GB RAM, диск 30–40 GB.
Выберите UEFI **до установки Ubuntu**, выключите Secure Boot. Для простоты
используйте SATA или NVMe и обычную установку без LUKS/TPM auto-unlock.

В выключенной VM:

1. VM Settings → Options → Advanced: Firmware = UEFI, Secure Boot выключен.
2. Options → Access Control → Encrypt: включите шифрование, необходимое для vTPM.
   Если версия предлагает шифровать только файлы, необходимые для TPM,
   этого достаточно для теста. Сохраните пароль шифрования VM.
3. Hardware → Add → Trusted Platform Module.

Названия пунктов отличаются между версиями. Инструкция рассчитана на
Workstation Pro, не Player. Если TPM нет в списке, проверьте редакцию,
UEFI и шифрование. Официальная справка Broadcom:
https://knowledge.broadcom.com/external/article/315650

После установки Ubuntu отключите установочный ISO. Не меняйте VM hardware,
Secure Boot и EFI-запись между регистрацией и последующим открытием секрета.
До теста сохраните исходное состояние VM, чтобы вернуть обычную загрузку.

## 2. Инструменты в Ubuntu

```sh
sudo apt update
sudo apt install -y build-essential curl ca-certificates python3 unzip file \
  kmod zstd xz-utils busybox-static tpm2-tools libtpms0 efibootmgr mokutil

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --profile minimal
. "$HOME/.cargo/env"
```

Проверьте VM:

```sh
test -d /sys/firmware/efi && echo 'UEFI OK'
mokutil --sb-state
ls -l /dev/tpm*
sudo tpm2_getcap properties-fixed
sudo tpm2_pcrread 'sha256:0,2,4,7,11'
sudo test -s /sys/kernel/security/tpm0/binary_bios_measurements \
  && echo 'TPM event log available'
```

Ожидаются выключенный Secure Boot, /dev/tpm0 и /dev/tpmrm0, TPM 2.0 и SHA-256
PCR. Если securityfs не смонтирован, сначала выполните
`sudo mount -t securityfs securityfs /sys/kernel/security`.
Наличие TPM само по себе не доказывает корректность Measured Boot прошивки:
наш EFI дополнительно проверяет журнал при запуске.

Перенесите архив проекта в VM: скачайте через браузер Ubuntu или скопируйте
из Windows. Распакуйте в домашнюю директорию Linux, не на Windows shared folder:

```sh
unzip tpm-initrd-boot-v0.1.0.zip
cd tpm-initrd-boot
chmod +x scripts/*.sh scripts/*.py tests/*.py
```

## 3. Сначала программные тесты

```sh
bash scripts/test.sh
```

Этот тест использует libtpms и не изменяет vTPM вашей VM. Должны пройти unit/CLI
тесты и появиться PASS для перезапуска, изменения PCR и независимого TPM.

## 4. Соберите со своим ключом

```sh
mkdir -m 700 keys
cargo run --locked -p initrdctl -- keygen "$PWD/keys/signing.key" "$PWD/keys/public.bin"
bash scripts/build.sh "$PWD/keys/public.bin"
```

Получатся dist/tpmboot.efi, dist/initrdctl и dist/public.bin.
Закрытый ключ остаётся в keys/signing.key внутри доверенной Ubuntu;
не копируйте его в initramfs или на EFI-раздел.

## 5. Подготовьте отдельный тестовый initramfs

Определите ESP вашей **гостевой Ubuntu**:

```sh
findmnt /boot/efi
lsblk -o NAME,PATH,FSTYPE,SIZE,MOUNTPOINTS
```

Ниже пример с `/dev/nvme0n1p1`. Если findmnt показывает `/dev/sda1`,
используйте именно `/dev/sda1`. Ничего форматировать не нужно.

```sh
sudo python3 scripts/vmware-lab.py --ack-lab-only \
  --esp-device /dev/nvme0n1p1 --output lab

dist/initrdctl sign keys/signing.key lab/vmlinuz lab/initramfs.img \
  'console=tty0 loglevel=4' manifest-lab.bin
```

Генератор берёт установленное ядро `/boot/vmlinuz-$(uname -r)`, статический
BusyBox, наш initrdctl и зависимости модулей TPM/диска/FAT из установленного
ядра. Модули распаковываются в обычные .ko, поэтому BusyBox не требуется
поддержка .zst. Результат — отдельный минимальный Linux в RAM, без монтирования
корня установленной Ubuntu и без изменения её штатного initramfs.

Если ядро обновлено, но система ещё не перезагружалась, сначала перезагрузите
обычную Ubuntu, чтобы uname, /boot и /lib/modules соответствовали друг другу.

Этот initramfs предназначен **только для лаборатории**: он автоматически
регистрирует новый случайный тестовый секрет и сравнивает его после перезапуска.
Не используйте его как production /init. В основной реализации регистрация
остаётся явным доверенным действием.

## 6. Установите лабораторный комплект в ESP

```sh
sudo python3 scripts/stage-esp.py /boot/efi \
  lab/vmlinuz lab/initramfs.img manifest-lab.bin dist
```

Скрипт создаст отдельный EFI/TPMBOOT. Если он уже существует, остановится,
ничего не перезаписывая. Не удаляйте чужую установку автоматически.

Посмотрите диск и номер раздела ESP. Пример для /dev/nvme0n1p1:

```sh
sudo efibootmgr --create --disk /dev/nvme0n1 --part 1 \
  --label TPMBOOT-LAB --loader '\EFI\TPMBOOT\tpmboot.efi'
sudo efibootmgr -v
```

Для /dev/sda1 замените `--disk /dev/nvme0n1` на `--disk /dev/sda`.
Убедитесь, что TPMBOOT-LAB стоит первым в постоянном BootOrder.
Если нужно менять порядок, сохраните также номера остальных записей и включите
их в `efibootmgr --bootorder ...`. Не задавайте один и тот же примерный номер
на разных машинах и не используйте одноразовый BootNext для регистрации.

Штатная запись Ubuntu остаётся доступной. Не устанавливайте наш EFI вместо
shim/grub и не копируйте его в EFI/BOOT/BOOTX64.EFI.

## 7. Две загрузки

```sh
sudo reboot
```

Первая загрузка должна показать:

```text
TPMBOOT LAB: first boot, enrollment of a random TEST secret
TPMBOOT LAB: enrollment complete; rebooting through the same EFI entry
```

Тестовый секрет создаётся только в /run первой загрузки; на ESP записываются
sealed.bin и хеш для лабораторного сравнения. Открытый секрет туда не пишется.

VM автоматически перезапустится. При второй загрузке ожидается:

```text
TPMBOOT LAB: consumer verified 64 bytes without displaying the secret
TPMBOOT LAB PASS: same 64 bytes recovered after reboot; handoff file removed
```

После PASS останется BusyBox shell в RAM. Это ожидаемо: рабочая Ubuntu не
запускается в лабораторном сценарии. `reboot -f` повторяет тест открытия,
`poweroff -f` выключает VM. Чтобы вернуться к Ubuntu, выберите её запись через
VMware Power On to Firmware / Boot Manager. Перед регистрацией BootOrder
должен быть уже окончательно настроен; смена пути загрузки может изменить PCR.

## 8. Отрицательные проверки

- Из обычной Ubuntu измените тестовую копию ядра или initramfs на ESP:
  следующая загрузка TPMBOOT должна остановиться до выдачи секрета.
- Изменение манифеста без подписи тоже должно блокировать загрузку.
- Удаление контейнера не должно автоматически создавать новый: enroll.request
  уже удалён. Появление обоих файлов тоже считается ошибкой режима.
- Для проверки другого TPM используйте новую VM с новым vTPM и переносите
  только EFI-файлы/диск. Копирование всей папки VM или clone может копировать
  состояние vTPM; такой опыт не доказывает привязку к другому TPM.
- Очистку/замену vTPM выполняйте только в отдельной тестовой копии: по выбранной
  модели восстановление исходного секрета после этого не предусмотрено.

## Если не заработало

| Симптом | Что проверить |
| --- | --- |
| Нет TPM в настройках | Workstation Pro, UEFI, шифрование VM |
| Нет /dev/tpmrm0 | vTPM, TPM-драйвер гостя, вывод dmesg |
| EFI возвращает SECURITY_VIOLATION до Linux | Подпись/хеши или журнал измерения своего EFI; это может быть несовместимость профиля VMware |
| initramfs не видит ESP | Правильность --esp-device, модули текущего ядра, SATA/NVMe |
| TPM enrollment завершился ошибкой | /dev/tpmrm0, SHA-256 bank, пустая owner auth, точный снимок из EFI |
| Первая загрузка успешна, вторая не открывает | Не менялись ли BootOrder, firmware, ISO, VM hardware или загрузочный комплект |
| Вместо нашего экрана стартует Ubuntu | BootOrder и путь отдельной EFI-записи |

Для разбора ошибки сохраните фото полного экрана, версию Workstation,
`uname -r`, `sudo efibootmgr -v`, `sudo tpm2_pcrread 'sha256:0,2,4,7,11'`.
PCR из работающей обычной Ubuntu не обязаны совпадать с ранним снимком EFI;
это диагностические данные, не замена регистрационного снимка.
