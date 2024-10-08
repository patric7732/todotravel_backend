package org.example.todotravel.domain.plan.repository;

import org.example.todotravel.domain.plan.entity.Plan;
import org.example.todotravel.domain.plan.entity.Schedule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScheduleRepository extends JpaRepository<Schedule, Long> {
    //플랜 상세 조회 - 김민정
    List<Schedule> findAllByPlan(Plan plan);

    @Modifying
    @Query("DELETE FROM Schedule s WHERE s.plan = :plan")
    void deleteAllByPlan(@Param("plan") Plan plan);
}
