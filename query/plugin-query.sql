SELECT
  COUNT(*) AS `COUNT`
FROM
  `information_schema`.`PLUGINS` AS `plg`
WHERE
  `plg`.`PLUGIN_NAME` = 'validate_password'
  AND
    `plg`.`PLUGIN_STATUS` = 'ACTIVE';