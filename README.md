## Пакет шифрования, который работает с шифром Цезаря

За основу криптографического алфавита взяты все буквы русского алфавита и знаки  
пунктуации (. , ”” : - ! ? ПРОБЕЛ). Символы, которые не входят в  
криптографический алфавит, пропускаются.  

### Основные возможности  
#### Имеет **2** режима:  
1. **Шифрование / расшифровка.**
2. **Криптоанализ.**

#### Методы криптоанализа  
1. **Brute force** (брутфорс, поиск грубой силой), путем перебора, подбирает ключ и расшифровывает текст.
2. **Статистический анализ**. Требуется дополнительный файл для стат.анализа.
Составляет статистику вхождения символов и после этого пытается использовать полученную статистику для криптоанализа зашифрованного текста.