SELECT
  CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`
FROM
  `mysql`.`user` AS `usr`
WHERE
  `usr`.`AUTHENTICATION_STRING` = ''
  OR
    `usr`.`AUTHENTICATION_STRING` IS NULL
  AND
    `usr`.`PLUGIN` NOT IN (
      'unix_socket',
      'win_socket'
    );