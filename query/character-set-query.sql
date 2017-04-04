SELECT
  `col`.`CHARACTER_SET_NAME` AS `CHARACTER_SET_NAME`
FROM
  `information_schema`.`COLUMNS` AS `col`
WHERE
  `col`.`CHARACTER_SET_NAME` IS NOT NULL
  AND
    `col`.`TABLE_SCHEMA` = :TABLE_SCHEMA
GROUP BY
  `col`.`CHARACTER_SET_NAME`;
