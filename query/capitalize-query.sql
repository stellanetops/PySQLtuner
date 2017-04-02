SELECT
  CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`
FROM
  `mysql`.`user` AS `usr`
WHERE
    CAST(`usr`.`:password_column` AS BINARY) = PASSWORD(`usr`.`USER`)
    OR
      CAST(`usr`.`:password_column` AS BINARY) = PASSWORD(UPPER(`usr`.`USER`))
    OR
      CAST(`usr`.`:password_column` AS BINARY) = PASSWORD(
        CONCAT(UPPER(LEFT(`usr`.`USER`, 1)), SUBSTRING(`usr`.`USER`, 2, LENGTH(`usr`.`USER`)))
      );